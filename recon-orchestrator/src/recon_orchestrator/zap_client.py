"""Thin async client for the OWASP ZAP REST API — active scanning via ZAP.

ZAP is a real DAST engine; this drives its spider + active scanner against a
target you own and pulls back the alerts, mapping them into the harness's
signal model. It talks to ZAP's documented JSON API over httpx, so it needs no
extra dependency.

Flow: spider (discover URLs) -> active scan (attack them) -> alerts. Both scans
are asynchronous in ZAP, so each is polled to completion with an overall time
budget. The active scan is genuinely aggressive — this is why the whole mode is
owned-assets-only and off by default.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

log = logging.getLogger(__name__)

# ZAP risk -> priority score. A High-risk ZAP alert (e.g. SQLi) far outweighs a
# passive header nit, but stays a *lead* to verify, not a confirmed bug.
_RISK_SCORE = {"High": 15, "Medium": 8, "Low": 3, "Informational": 1}
_RISK_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}


class ZapError(RuntimeError):
    pass


class ZapClient:
    def __init__(self, api_url: str, api_key: str, timeout: float = 30.0,
                 transport: httpx.AsyncBaseTransport | None = None,
                 poll_interval: float = 3.0) -> None:
        self._base = api_url.rstrip("/")
        self._key = api_key
        self._poll = poll_interval
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)

    async def __aenter__(self) -> "ZapClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self._client.aclose()

    async def _get(self, view_or_action: str, **params) -> dict:
        params["apikey"] = self._key
        url = f"{self._base}/JSON/{view_or_action}/"
        resp = await self._client.get(url, params=params)
        if resp.status_code != 200:
            raise ZapError(f"ZAP {view_or_action} -> HTTP {resp.status_code}: "
                           f"{resp.text[:200]}")
        return resp.json()

    async def version(self) -> str:
        return (await self._get("core/view/version"))["version"]

    async def _run_and_wait(self, action: str, status_view: str, url: str,
                            max_wait: float) -> None:
        """Start an async ZAP scan and poll its status view to 100%.

        On ANY early exit that is not completion — the time budget elapsing, or
        the caller being cancelled (you quit the TUI / Ctrl-C mid-scan) — the
        scan is stopped so ZAP does not keep attacking the target in the
        background.
        """
        started = await self._get(action, url=url)
        scan_id = started.get("scan")
        if scan_id is None:
            raise ZapError(f"{action} did not return a scan id: {started}")

        completed = False
        try:
            deadline = asyncio.get_event_loop().time() + max_wait
            while asyncio.get_event_loop().time() < deadline:
                status = (await self._get(status_view, scanId=scan_id)).get("status", "0")
                if str(status) == "100":
                    completed = True
                    return
                await asyncio.sleep(self._poll)
            log.warning("ZAP scan hit the time budget — stopping it",
                        extra={"action": action, "url": url, "max_wait": max_wait})
        finally:
            if not completed:
                # Shield the stop so a cancellation still delivers it to ZAP.
                stop_action = action.rsplit("/", 1)[0] + "/stop"
                try:
                    await asyncio.shield(self._get(stop_action, scanId=scan_id))
                except asyncio.CancelledError:
                    raise          # propagate; the stop was already dispatched
                except Exception:  # noqa: BLE001 - best-effort stop
                    pass

    async def add_request_header(self, name: str, value: str) -> None:
        """Make ZAP send ``name: value`` on every request (spider + scan).

        Uses ZAP's Replacer so a protected preview can be reached with a
        bypass token. Best-effort — a failure just means the header is not set.
        """
        try:
            await self._get(
                "replacer/action/addRule",
                description=f"harness:{name}", enabled="true",
                matchType="REQ_HEADER", matchRegex="false",
                matchString=name, replacement=value, initiators="",
            )
        except ZapError as exc:
            log.warning("could not add ZAP header rule",
                        extra={"header": name, "error": str(exc)})

    async def remove_request_header(self, name: str) -> None:
        try:
            await self._get("replacer/action/removeRule",
                            description=f"harness:{name}")
        except ZapError:
            pass

    async def alerts(self, baseurl: str) -> list[dict]:
        data = await self._get("core/view/alerts", baseurl=baseurl)
        return data.get("alerts", [])

    async def scan(self, target: str, max_wait: float = 300.0) -> list[dict]:
        """Spider, then active-scan ``target``, then return its alerts.

        The time budget is split between the two scans.
        """
        half = max_wait / 2
        await self._run_and_wait("spider/action/scan", "spider/view/status",
                                 target, half)
        await self._run_and_wait("ascan/action/scan", "ascan/view/status",
                                 target, max_wait - half)
        return await self.alerts(target)


def alert_host(alert: dict) -> str:
    from urllib.parse import urlparse
    return urlparse(alert.get("url", "")).hostname or ""


def alerts_to_signals(
    alerts: list[dict], min_risk: str = "Low"
) -> tuple[list[str], int]:
    """Turn ZAP alerts into (signals, total_score), highest risk first.

    Alerts below ``min_risk`` are dropped — those are the missing-header,
    cookie-flag and version-leak nits that programs exclude — and the count of
    what was hidden is appended as one line so nothing silently vanishes.
    De-duplicates by (alert name, url, param).
    """
    from urllib.parse import urlparse

    floor = _RISK_ORDER.get(min_risk, 0)
    ranked = sorted(alerts, key=lambda a: -_RISK_ORDER.get(a.get("risk", "Low"), 0))

    signals: list[str] = []
    score = 0
    hidden = 0
    seen: set[tuple[str, str, str]] = set()
    for a in ranked:
        name = a.get("alert") or a.get("name") or "ZAP alert"
        risk = a.get("risk", "Low")
        url = a.get("url", "")
        param = a.get("param", "")
        key = (name, url, param)
        if key in seen:
            continue
        seen.add(key)
        if _RISK_ORDER.get(risk, 0) < floor:
            hidden += 1
            continue
        path = urlparse(url).path or "/"
        where = f" at {path}" + (f" via '{param}'" if param else "")
        signals.append(f"[ZAP {risk}] {name}{where} — verify manually")
        score += _RISK_SCORE.get(risk, 1)

    if hidden:
        signals.append(f"({hidden} lower-risk ZAP alert(s) hidden — "
                       f"lower zap_min_risk to see them)")
    return signals, score
