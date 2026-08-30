"""Pure scheduling logic for the nightly runner.

The nightly harness runs every configured program in turn, unattended, and
emits a ranked queue for a human to review in the morning. This module holds
only the *pure* decision logic — when to run, in what order, and how to merge
per-program results into one queue. No network, no asyncio, no I/O, so it is
unit-testable deterministically.

Every program is still bound by the same guarantees as interactive recon:
its authorized scope is enforced host-by-host and only GET/HEAD probes are ever
sent. The nightly runner is a *loop over programs*, never a loosening of policy.
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class Schedule:
    """Which programs to run and in what priority order.

    ``order`` is a list of program names; the runner executes them in that
    sequence. A missing program (e.g. deleted since config was written) is
    simply skipped by the runner, never invented.
    """

    order: list[str] = field(default_factory=list)

    @classmethod
    def from_names(cls, names: list[str]) -> "Schedule":
        # Dedup preserving order; the runner tolerates unknown names later.
        seen: set[str] = set()
        ordered = [n for n in names if not (n in seen or seen.add(n))]
        return cls(order=ordered)


# A merged queue item. ``program`` lets the human know which engagement the
# lead came from; everything else is the lead's own data.
@dataclass(frozen=True)
class QueueItem:
    program: str
    host: str
    url: str | None
    priority_score: int
    signals: tuple[str, ...]
    note: str


def merge_queue(
    per_program: dict[str, list[dict]],
    min_score: int = 1,
) -> list[QueueItem]:
    """Flatten per-program candidate leads into one ranked morning queue.

    Higher ``priority_score`` first; ties broken by (program, host) for stable,
    reviewable output. Leads at or below ``min_score`` are dropped — a queue
    full of noise is not a queue a human will use.

    Returns QueueItems (frozen, hashable) so callers can dedupe deterministically.
    """
    items: list[QueueItem] = []
    for program, leads in per_program.items():
        for lead in leads:
            score = int(lead.get("priority_score", 0) or 0)
            if score < min_score:
                continue
            items.append(QueueItem(
                program=program,
                host=str(lead.get("host", "")),
                url=lead.get("url"),
                priority_score=score,
                signals=tuple(lead.get("signals", []) or []),
                note=str(lead.get("note", "")),
            ))
    # Reverse-sort by score; heapq is used so the sort is explicit about stability.
    ranked = sorted(items, key=lambda it: (-it.priority_score, it.program, it.host))
    heapq.heapify([])  # no-op, documents intent: ranked list is the queue
    return ranked


def build_schedule(
    configured_order: list[str],
    available: list[str],
    prefer: Callable[[str], int] | None = None,
) -> Schedule:
    """Reconcile a desired run order against programs that actually exist.

    - Programs in ``configured_order`` that are also ``available`` run first,
      in the configured order.
    - Any ``available`` program not listed is appended at the end (so a newly
      added program is never silently skipped).
    - ``prefer`` (optional) can nudge ordering, e.g. put high-bounty programs
      first; it must return a sortable key, lower = earlier.

    Programs in the config that are NOT available are dropped (never invented).
    """
    want = [n for n in configured_order if n in available]
    extra = [n for n in available if n not in want]
    order = want + extra
    if prefer is not None:
        order.sort(key=prefer)
    return Schedule(order=order)
