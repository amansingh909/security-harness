"""Async recon state machine for ONE authorized target.

Phases: SEED -> RESOLVE(scope-gate) -> PROBE -> FINGERPRINT -> CVE_MATCH ->
TRIAGE -> REPORT. Every host is scope-checked before it is touched; only a clean
IN verdict is probed. Concurrency is bounded and rate-limited (politeness, not
evasion). SIGINT/SIGTERM trigger a graceful drain: stop scheduling new work,
let in-flight probes finish, close the client, emit whatever was gathered.
"""
from __future__ import annotations

import asyncio
import logging
import signal

from .config import Settings
from .cve_lookup import lookup as cve_lookup
from .http_probe import HttpProber
from .models import CandidateFinding, CveCandidate, HostProbe
from .ratelimit import TokenBucket
from .scope import ScopeGuard
from .triage import triage

log = logging.getLogger(__name__)


class ReconOrchestrator:
    def __init__(self, settings: Settings, scope: ScopeGuard) -> None:
        self._s = settings
        self._scope = scope
        self._shutdown = asyncio.Event()
        self._sem = asyncio.Semaphore(settings.max_concurrency)

    def request_shutdown(self) -> None:
        if not self._shutdown.is_set():
            log.warning("shutdown requested; draining in-flight probes")
            self._shutdown.set()

    def _authorized_seeds(self, seeds: list[str]) -> list[str]:
        allowed: list[str] = []
        for host in seeds:
            verdict = self._scope.verdict(host)
            if verdict.status == "in":
                allowed.append(host)
            else:
                log.warning("skipping host: not authorized",
                            extra={"host": host, "verdict": verdict.status,
                                   "reason": verdict.reason})
        return allowed

    async def _probe_one(
        self, prober: HttpProber, host: str
    ) -> tuple[HostProbe, list[CveCandidate], list[str]]:
        async with self._sem:
            if self._shutdown.is_set():
                return HostProbe(host=host, error="skipped: shutting down"), [], []
            probe = await prober.probe(host)
            active_signals: list[str] = []
            if self._s.active_tests and not probe.error:
                active_signals = await self._run_active_tests(prober, probe)
            candidates: list[CveCandidate] = []
            if probe.fingerprints and self._s.cve_index_url and not probe.error:
                try:
                    candidates = await cve_lookup(
                        probe.fingerprints, self._s.cve_index_url, self._s.http_timeout
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("cve correlation failed",
                                extra={"host": host, "error": str(exc)})
            return probe, candidates, active_signals

    async def _discover_subdomains(self, hosts: list[str]) -> list[str]:
        """Passive subdomain discovery via crt.sh, filtered back through scope.

        Only in-scope names are returned, so on a program scoped to a fixed
        host list (no wildcard) this adds nothing — which is correct.
        """
        from .subdomain_enum import fetch_crtsh_for_apex

        apexes = {self._apex_of(h) for h in hosts}
        apexes.discard("")
        # Only query an apex whose scope would authorize a NEW subdomain. A
        # fixed host-list scope (no wildcard) can never gain a discovered host,
        # so querying crt.sh for it is pure latency — and crt.sh is often slow.
        apexes = [
            a for a in sorted(apexes)
            if self._scope.verdict(f"scope-probe-8f3a2b.{a}").status == "in"
        ]
        if not apexes:
            return []

        # Query apexes concurrently so a slow/unreachable crt.sh costs one
        # timeout total, not one per apex. gather preserves input order, so the
        # apex/result pairing below is correct.
        results = await asyncio.gather(
            *(fetch_crtsh_for_apex(a) for a in apexes), return_exceptions=True
        )
        found: set[str] = set()
        for apex, result in zip(apexes, results):
            if isinstance(result, set):
                found |= result
            else:
                log.warning("subdomain enum failed",
                            extra={"apex": apex, "error": str(result)})

        known = {h.lower() for h in hosts}
        new_authorized = [
            name for name in sorted(found)
            if name not in known and self._scope.verdict(name).status == "in"
        ]
        if new_authorized:
            log.info("subdomain enum added hosts",
                     extra={"discovered": len(found), "in_scope_new": len(new_authorized)})
        return new_authorized

    @staticmethod
    def _apex_of(host: str) -> str:
        """Best-effort registrable apex: the last two labels. Imperfect for
        multi-part TLDs (co.uk), which is acceptable for a crt.sh query."""
        parts = host.strip().lower().strip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else ""

    async def _enrich_sensitive(self, findings: list[CandidateFinding],
                                probes: list[HostProbe]) -> None:
        """Run GET-only sensitive-path checks on live hosts and fold the
        results into findings as scored signals. A clean host that only exposes
        a secret gets a finding created for it; triage would otherwise drop it.
        """
        from .sensitive_checks import run_sensitive_checks

        by_host = {f.host: f for f in findings}
        live = sorted({p.host for p in probes if not p.error})
        for host in live:
            if self._shutdown.is_set():
                break
            try:
                async with self._sem:
                    hits = await run_sensitive_checks(host, self._s)
            except Exception as exc:  # noqa: BLE001
                log.warning("sensitive checks failed",
                            extra={"host": host, "error": str(exc)})
                continue

            signals, score = self._sensitive_signals(hits)
            if not signals:
                continue
            existing = by_host.get(host)
            if existing is not None:
                existing.signals.extend(signals)
                existing.priority_score += score
            else:
                new = CandidateFinding(
                    host=host, url=f"https://{host}",
                    priority_score=score, signals=signals,
                )
                findings.append(new)
                by_host[host] = new

    @staticmethod
    def _sensitive_signals(hits: list[HostProbe]) -> tuple[list[str], int]:
        """Turn sensitive-check probes into signals. An exposed VCS/secret file
        is near-reportable, so it scores far above a header nit."""
        signals: list[str] = []
        score = 0
        for hit in hits:
            path = (hit.url or "").split(hit.host, 1)[-1] or hit.url or ""
            if hit.title == "Security Headers/Cookies Analysis":
                signals.append(f"missing/weak security headers on {hit.host}:{hit.port}")
                score += 1
            else:
                signals.append(
                    f"sensitive path exposed ({path}) — information disclosure"
                )
                score += 6
        return signals, score

    async def _run_active_tests(self, prober: HttpProber, probe: HostProbe) -> list[str]:
        """Active testing for a host — OWNED ASSETS ONLY.

        Reached only when ``active_tests`` is set. Routes to a real OWASP ZAP
        scan when ``use_zap`` is on, otherwise the lightweight built-in tester.
        Uses the URL the probe actually reached, so an http-only host or a
        non-standard port is tested correctly instead of a guessed https URL.
        """
        host = probe.host
        base = (probe.url or f"https://{host}").rstrip("/")
        # Loud, per-host record that active traffic is being sent.
        log.warning("active tests enabled — sending crafted input to owned target",
                    extra={"host": host, "engine": "zap" if self._s.use_zap else "builtin"})
        if self._s.use_zap:
            return await self._run_zap(host, base)
        return await self._run_builtin_active(prober, host, base)

    async def _run_zap(self, host: str, base: str) -> list[str]:
        """Drive an OWASP ZAP spider + active scan against ``base``.

        Alerts are filtered back through scope, so even if ZAP's spider wandered
        off-host, only in-scope findings are reported.
        """
        from .zap_client import ZapClient, alert_host, alerts_to_signals

        if not self._s.zap_api_url or not self._s.zap_api_key:
            log.warning("use_zap set but ZAP_API_URL / ZAP_API_KEY are missing",
                        extra={"host": host})
            return []
        try:
            async with ZapClient(self._s.zap_api_url, self._s.zap_api_key) as zap:
                alerts = await zap.scan(base, max_wait=self._s.zap_max_wait)
        except Exception as exc:  # noqa: BLE001 - ZAP down / unreachable
            log.warning("ZAP scan failed", extra={"host": host, "error": str(exc)})
            return []

        in_scope = [
            a for a in alerts
            if self._scope.verdict(alert_host(a) or host).status == "in"
        ]
        signals, _score = alerts_to_signals(in_scope, min_risk=self._s.zap_min_risk)
        return signals

    async def _run_builtin_active(self, prober: HttpProber, host: str, base: str) -> list[str]:
        """Lightweight built-in tester: discover a page's inputs, scope-check
        each, inject the payloads. Marker/signature detection, rate-limited.
        No external dependency — the fallback when ZAP is not configured.
        """
        import httpx

        from . import payloads
        from .active_discovery import (
            MAX_CRAWL_PAGES, extract_injection_points, extract_links, inject,
        )

        # 1. Bounded same-host crawl to discover inputs — many params live a
        #    page or two deeper than the landing page, so a single fetch misses
        #    them. Only in-scope pages are visited.
        points: list = []
        point_keys: set[tuple[str, str]] = set()
        visited: set[str] = set()
        queue: list[str] = [base + "/"]
        while queue and len(visited) < MAX_CRAWL_PAGES:
            if self._shutdown.is_set():
                break
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            page_host = httpx.URL(url).host
            if self._scope.verdict(page_host or host).status != "in":
                continue
            try:
                page = await prober.send(httpx.Request("GET", url))
            except Exception:  # noqa: BLE001
                continue
            body = page.text or ""
            for pt in extract_injection_points(str(page.url), body):
                key = (pt.url, pt.param)
                if key not in point_keys:
                    point_keys.add(key)
                    points.append(pt)
            for link in extract_links(str(page.url), body):
                if link not in visited and httpx.URL(link).host == page_host:
                    queue.append(link)

        if not points:
            log.info("active tests: no injectable parameters found",
                     extra={"host": host, "pages_crawled": len(visited)})
            return []

        # 2. Inject into each in-scope discovered parameter.
        signals: list[str] = []
        seen: set[str] = set()
        for point in points:
            if self._shutdown.is_set():
                break
            # Never send payloads to a host the scope does not authorize, even
            # if the page linked to it.
            if self._scope.verdict(point.host or host).status != "in":
                continue
            for test in payloads.TESTS:
                if self._shutdown.is_set():
                    break
                try:
                    resp = await prober.send(
                        httpx.Request("GET", inject(point, test.value))
                    )
                except Exception:  # noqa: BLE001
                    continue
                desc = payloads.interpret(test, resp.text or "")
                if desc:
                    signal = f"{desc} at {point.path} via '{point.param}'"
                    if signal not in seen:
                        seen.add(signal)
                        signals.append(signal)
        return signals

    async def run(self, seeds: list[str], prober: HttpProber | None = None) -> list[CandidateFinding]:
        authorized = self._authorized_seeds(seeds)
        if not authorized:
            log.error("no authorized seed hosts; nothing to do")
            return []

        # Stage 1: passive subdomain discovery expands the host set (scope-gated).
        if self._s.enable_subdomain_enum and not self._shutdown.is_set():
            authorized = authorized + await self._discover_subdomains(authorized)

        # Stage 1b: optional port sweep adds probes on non-standard ports.
        extra_probes: list[HostProbe] = []
        if self._s.enable_port_sweep and not self._shutdown.is_set():
            try:
                from .tech_detect import sweep_ports
                extra_probes = await sweep_ports(authorized, self._s)
            except Exception as exc:  # noqa: BLE001
                log.warning("port sweep failed", extra={"error": str(exc)})

        log.info("recon starting",
                 extra={"authorized_hosts": len(authorized),
                        "rps": self._s.requests_per_second})

        owns_prober = prober is None
        if owns_prober:
            bucket = TokenBucket(self._s.requests_per_second)
            prober = HttpProber(self._s, bucket)
        try:
            tasks = [
                asyncio.create_task(self._probe_one(prober, host))
                for host in authorized
            ]
            probes: list[HostProbe] = list(extra_probes)
            cve_by_host: dict[str, list[CveCandidate]] = {}
            active_by_host: dict[str, list[str]] = {}
            for coro in asyncio.as_completed(tasks):
                result = await coro
                # _probe_one now returns (probe, candidates, active_signals)
                probe, candidates, active_signals = result
                probes.append(probe)
                if candidates:
                    cve_by_host[probe.host] = candidates
                if active_signals:
                    active_by_host[probe.host] = active_signals
        finally:
            if owns_prober:
                await prober.aclose()

        findings = triage(probes)

        # Merge CVE candidates and active-test signals into findings.
        by_host = {f.host: f for f in findings}
        for finding in findings:
            finding.cve_candidates = cve_by_host.get(finding.host, [])

        # Active-test hits are near-confirmed vuln indicators (reflected input,
        # DB errors), so they score high. Attach to the host's finding, or
        # create one — an active hit on an otherwise-boring host that triage
        # dropped must still surface.
        for host, act in active_by_host.items():
            existing = by_host.get(host)
            if existing is not None:
                existing.signals.extend(act)
                existing.priority_score += len(act) * 5
            else:
                new = CandidateFinding(
                    host=host, url=f"https://{host}",
                    priority_score=len(act) * 5, signals=list(act),
                )
                findings.append(new)
                by_host[host] = new

        # Stage 3: GET-only sensitive-path checks, folded into findings.
        if self._s.enable_sensitive_checks and not self._shutdown.is_set():
            await self._enrich_sensitive(findings, probes)

        # Re-sort: enrichment changed scores and may have added hosts.
        findings.sort(key=lambda c: (-c.priority_score, c.host))
        log.info("recon complete",
                 extra={"probed": len(probes), "candidates": len(findings)})
        return findings


async def run_recon(settings: Settings, scope: ScopeGuard, seeds: list[str]) -> list[dict]:
    orchestrator = ReconOrchestrator(settings, scope)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, orchestrator.request_shutdown)
        except NotImplementedError:  # pragma: no cover - Windows
            pass
    findings = await orchestrator.run(seeds)
    return [f.model_dump() for f in findings]
