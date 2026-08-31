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
    ) -> tuple[HostProbe, list[CveCandidate]]:
        async with self._sem:
            if self._shutdown.is_set():
                return HostProbe(host=host, error="skipped: shutting down"), []
            probe = await prober.probe(host)
            candidates: list[CveCandidate] = []
            if probe.fingerprints and self._s.cve_index_url and not probe.error:
                try:
                    candidates = await cve_lookup(
                        probe.fingerprints, self._s.cve_index_url, self._s.http_timeout
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("cve correlation failed",
                                extra={"host": host, "error": str(exc)})
            return probe, candidates

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
            for coro in asyncio.as_completed(tasks):
                probe, candidates = await coro
                probes.append(probe)
                if candidates:
                    cve_by_host[probe.host] = candidates
        finally:
            if owns_prober:
                await prober.aclose()

        findings = triage(probes)

        # Stage 3: GET-only sensitive-path checks, folded into findings.
        if self._s.enable_sensitive_checks and not self._shutdown.is_set():
            await self._enrich_sensitive(findings, probes)

        for finding in findings:
            finding.cve_candidates = cve_by_host.get(finding.host, [])
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
