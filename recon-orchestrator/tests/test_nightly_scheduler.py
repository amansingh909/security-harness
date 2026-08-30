"""Unit tests for the pure nightly scheduling logic.

No network, no asyncio — just the merge/order decisions that the unattended
runner depends on. Deterministic and fast.
"""
import pytest

from recon_orchestrator.nightly.scheduler import (
    QueueItem,
    Schedule,
    build_schedule,
    merge_queue,
)


def _lead(host, score, program="acme", signals=None, note=""):
    return {
        "host": host,
        "program": program,
        "priority_score": score,
        "signals": signals or [],
        "note": note,
    }


def test_merge_queue_ranks_by_score_desc_then_stable():
    per = {
        "acme": [_lead("a.acme.com", 5), _lead("b.acme.com", 9), _lead("c.acme.com", 1)],
        "globex": [_lead("x.globex.com", 7)],
    }
    queue = merge_queue(per, min_score=1)
    scores = [it.priority_score for it in queue]
    assert scores == [9, 7, 5, 1]
    # lower-score item dropped by default threshold
    queue = merge_queue(per, min_score=3)
    assert [it.priority_score for it in queue] == [9, 7, 5]
    assert queue[0].host == "b.acme.com"


def test_merge_queue_drops_empty_signals_still_kept_on_score():
    per = {"acme": [_lead("silent.acme.com", 4, signals=[])]}
    queue = merge_queue(per, min_score=1)
    assert len(queue) == 1
    assert queue[0].program == "acme"


def test_build_schedule_prefers_configured_order_and_skips_missing():
    sched = build_schedule(
        configured_order=["acme", "DOES_NOT_EXIST", "globex"],
        available=["globex", "acme", "hooli"],
    )
    assert sched.order == ["acme", "globex", "hooli"]


def test_build_schedule_prefer_callback_sorts_both_segments():
    sched = build_schedule(
        configured_order=["acme", "globex"],
        available=["globex", "acme", "hooli"],
        prefer=lambda n: {"hooli": 0, "globex": 1, "acme": 2}[n],
    )
    assert sched.order == ["hooli", "globex", "acme"]


def test_schedule_from_names_dedups_preserving_order():
    sched = Schedule.from_names(["acme", "acme", "globex", "acme"])
    assert sched.order == ["acme", "globex"]


def test_queue_item_is_hashable_for_dedup():
    a = QueueItem("acme", "h.acme.com", None, 5, ("x",), "n")
    b = QueueItem("acme", "h.acme.com", None, 5, ("x",), "n")
    assert a == b
    assert len({a, b}) == 1
