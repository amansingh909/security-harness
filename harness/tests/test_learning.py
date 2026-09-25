"""The feedback loop: outcomes teach the queue what's worth your time."""
from __future__ import annotations

from harness import findings_store as fs, learning


def _rec(program, signals, status="needs_check", outcome="", bounty=0.0, score=5):
    return fs.FindingRecord(
        id=f"{program}:{abs(hash(tuple(signals))) % 10000}",
        program=program, signals=list(signals), status=status,
        outcome=outcome, bounty=bounty, priority_score=score)


def test_signal_type_classifies_the_common_signals():
    assert learning.signal_type("reflected input (unencoded) — possible XSS") == "xss"
    assert learning.signal_type("auth boundary (HTTP 403)") == "auth-boundary"
    assert learning.signal_type("sensitive path exposed (/info.php)") == "exposed-path"
    assert learning.signal_type("missing/weak security headers on x:443") == "weak-headers"
    assert learning.signal_type("version disclosed (apache 2.4.25) — CVE surface") == "version-cve"


def test_outcome_class_folds_in_all_three_goals():
    assert learning.outcome_class(_rec("p", ["x"], outcome="paid", bounty=500)) == "paid"
    assert learning.outcome_class(_rec("p", ["x"], status="real")) == "valid"
    assert learning.outcome_class(_rec("p", ["x"], status="false")) == "wasted"
    assert learning.outcome_class(_rec("p", ["x"])) == "pending"  # no verdict yet


def test_signal_weights_reward_paid_and_penalize_wasted():
    records = [
        _rec("p", ["auth boundary (HTTP 403)"], outcome="paid", bounty=500),
        _rec("p", ["auth boundary (HTTP 403)"], status="real"),
        _rec("p", ["missing/weak security headers"], status="false"),
        _rec("p", ["missing/weak security headers"], status="false"),
    ]
    w = learning.signal_weights(records)
    assert w["auth-boundary"] > w["weak-headers"]
    assert w["weak-headers"] < 0        # consistently wasted -> negative
    assert "pending" not in str(w)      # findings without a verdict don't vote


def test_learned_score_floats_the_high_value_signal_up():
    records = [
        _rec("p", ["auth boundary (HTTP 403)"], outcome="paid", bounty=500),
        _rec("p", ["missing/weak security headers"], status="false"),
    ]
    w = learning.signal_weights(records)
    good = _rec("p", ["auth boundary (HTTP 403)"], score=5)
    noise = _rec("p", ["missing/weak security headers"], score=5)
    assert learning.learned_score(good, w) > learning.learned_score(noise, w)


def test_no_history_means_no_change_to_ordering():
    # with zero verdicts, weights are empty and score == base priority
    w = learning.signal_weights([_rec("p", ["auth boundary (HTTP 403)"])])
    r = _rec("p", ["auth boundary (HTTP 403)"], score=7)
    assert learning.learned_score(r, w) == 7.0


def test_summarize_reports_per_program_and_total_bounty():
    records = [
        _rec("clear", ["auth boundary (HTTP 403)"], outcome="paid", bounty=750),
        _rec("clear", ["missing/weak security headers"], status="false"),
    ]
    s = learning.summarize(records)
    assert s["total_bounty"] == 750.0
    assert s["by_program"]["clear"]["paid"] == 1
    assert s["by_signal"]["weak-headers"]["wasted"] == 1
