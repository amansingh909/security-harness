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

    async def run(self, seeds: list[str], prober: HttpProber | None = None) -> list[CandidateFinding]:
        authorized = self._authorized_seeds(seeds)
        if not authorized:
            log.error("no authorized seed hosts; nothing to do")
            return []
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
            probes: list[HostProbe] = []
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
        for finding in findings:
            finding.cve_candidates = cve_by_host.get(finding.host, [])
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
