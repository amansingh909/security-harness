"""Nightly orchestration package: unattended, scope-gated, GET/HEAD-only.

The runner executes each configured program through the same scoped recon
pipeline used interactively, isolates per-program failures, and merges the
results into one ranked queue for a human to review. It never sends payloads
and never submits findings.
"""
from __future__ import annotations

from .runner import ProgramSpec, RunReport, run_nightly
from .scheduler import QueueItem, Schedule, build_schedule, merge_queue

__all__ = [
    "ProgramSpec",
    "RunReport",
    "run_nightly",
    "QueueItem",
    "Schedule",
    "build_schedule",
    "merge_queue",
]
