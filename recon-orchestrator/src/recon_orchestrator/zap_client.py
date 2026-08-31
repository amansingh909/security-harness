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
        """Start an async ZAP scan and poll its status view to 100%."""
        started = await self._get(action, url=url)
        scan_id = started.get("scan")
        if scan_id is None:
            raise ZapError(f"{action} did not return a scan id: {started}")
        deadline = asyncio.get_event_loop().time() + max_wait
        while asyncio.get_event_loop().time() < deadline:
            status = (await self._get(status_view, scanId=scan_id)).get("status", "0")
            if str(status) == "100":
                return
            await asyncio.sleep(self._poll)
        log.warning("ZAP scan did not finish within budget",
                    extra={"action": action, "url": url, "max_wait": max_wait})

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


def alerts_to_signals(alerts: list[dict]) -> tuple[list[str], int]:
    """Turn ZAP alerts into (signals, total_score).

    De-duplicates by (alert name, url, param) so the same issue on the same
    endpoint is reported once.
    """
    from urllib.parse import urlparse

    signals: list[str] = []
    score = 0
    seen: set[tuple[str, str, str]] = set()
    for a in alerts:
        name = a.get("alert") or a.get("name") or "ZAP alert"
        risk = a.get("risk", "Low")
        url = a.get("url", "")
        param = a.get("param", "")
        key = (name, url, param)
        if key in seen:
            continue
        seen.add(key)
        path = urlparse(url).path or "/"
        where = f" at {path}" + (f" via '{param}'" if param else "")
        signals.append(f"[ZAP {risk}] {name}{where} — verify manually")
        score += _RISK_SCORE.get(risk, 1)
    return signals, score
