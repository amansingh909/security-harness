"""Unattended nightly runner: drives every authorized program in sequence and
merges the results into one ranked queue.

This is the *machine*. It is deliberately conservative:

- Each program is run through the SAME scoped, GET/HEAD-only recon pipeline
  used interactively. No new network primitives are introduced here.
- The runner never sends a single payload and never submits anything. It writes
  a queue file the human reviews next. Submission is a separate, manual step.
- Per-program failures are isolated: if one program's scope is broken or its
  target is down, the others still run and the queue still gets written.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Settings
from ..orchestrator import ReconOrchestrator
from ..scope import ScopeGuard
from .scheduler import Schedule, merge_queue

log = logging.getLogger(__name__)


@dataclass
class ProgramSpec:
    """Everything needed to run one program unattended."""

    name: str
    in_scope: list[str]
    out_of_scope: list[str]
    seeds: list[str]
    seeds_file: str | None = None
    cve_index_url: str | None = None
    requests_per_second: float = 2.0
    allow_multilevel_wildcard: bool = True


@dataclass
class RunReport:
    ran: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    queue: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ran": self.ran,
            "failed": self.failed,
            "queue_size": len(self.queue),
            "queue": [item.__dict__ for item in self.queue],
        }


async def _run_one(spec: ProgramSpec) -> list[dict]:
    """Run one program's recon and return its candidate leads.

    Raises on unrecoverable error so the caller can isolate the failure.
    """
    settings = Settings(
        requests_per_second=spec.requests_per_second,
        cve_index_url=spec.cve_index_url,
    )
    scope = ScopeGuard(
        spec.in_scope, spec.out_of_scope, spec.allow_multilevel_wildcard
    )
    # Start with the provided seeds
    seeds = list(spec.seeds)
    if spec.seeds_file:
        p = Path(spec.seeds_file)
        if p.exists():
            seeds += [
                line.strip()
                for line in p.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")
            ]
    # Expand seeds to include their base domain (e.g., "x.example.com" -> "example.com")
    expanded: set[str] = set(seeds)
    for s in seeds:
        if "." in s:
            parts = s.split(".")
            if len(parts) > 1:
                expanded.add(".".join(parts[1:]))
    seeds = list(expanded)
    # Reuse the same entrypoint the CLI uses; it is scope-gated internally too.
    from ..orchestrator import run_recon

    return await run_recon(settings, scope, seeds)


async def run_nightly(
    schedule: Schedule,
    specs: dict[str, ProgramSpec],
    min_score: int = 1,
) -> RunReport:
    """Execute the schedule, isolating per-program failures, and merge a queue.

    Programs listed in ``schedule.order`` but absent from ``specs`` are skipped.
    A program whose run raises is recorded under ``failed`` and excluded from the
    queue; the rest proceed.
    """
    report = RunReport()
    per_program: dict[str, list[dict]] = {}
    for name in schedule.order:
        spec = specs.get(name)
        if spec is None:
            log.warning("skipping program in schedule but not configured",
                        extra={"program": name})
            continue
        try:
            # Prepare settings and scope for this program
            settings = Settings(
                requests_per_second=spec.requests_per_second,
                cve_index_url=spec.cve_index_url,
            )
            scope = ScopeGuard(
                spec.in_scope, spec.out_of_scope, spec.allow_multilevel_wildcard
            )
            # Seed handling (same logic as _run_one)
            seeds = list(spec.seeds)
            if spec.seeds_file:
                p = Path(spec.seeds_file)
                if p.exists():
                    seeds += [
                        line.strip()
                        for line in p.read_text(encoding="utf-8").splitlines()
                        if line.strip() and not line.startswith("#")
                    ]
            # Expand seeds to include base domains
            expanded: set[str] = set(seeds)
            for s in seeds:
                if "." in s:
                    parts = s.split(".")
                    if len(parts) > 1:
                        expanded.add(".".join(parts[1:]))
            seeds = list(expanded)
            # Run recon (patched in tests)
            from ..orchestrator import run_recon
            leads = await run_recon(settings, scope, seeds)
            per_program[name] = leads
            report.ran.append(name)
            log.info("nightly program done",
                     extra={"program": name, "leads": len(leads)})
        except Exception as exc:  # noqa: BLE001 - isolate failure
            report.failed[name] = str(exc)
            log.exception("nightly program failed",
                           extra={"program": name, "error": str(exc)})
    report.queue = merge_queue(per_program, min_score=min_score)
    return report
