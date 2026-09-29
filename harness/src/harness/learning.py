"""Learn from finding outcomes so the review queue gets better over time.

This is not model training — it's a feedback loop. Record what each finding
became (false / real / duplicate / triaged / paid), then boost the signal types
and programs that have led to valid, paid bugs and sink the ones that only ever
waste your time. It folds in all three goals at once: **paid > valid >
time-wasted**.

Once enough outcomes accumulate, this ledger is exactly the labelled data to
train a real lead-quality model on (reuse the cve-classifier QLoRA setup).
"""
from __future__ import annotations

# Signal wording -> a stable type we can learn per-type weights for.
_SIGNAL_TYPES = [
    ("xss", ["xss", "reflected input"]),
    ("sqli", ["sql error", "sqli", "sql injection"]),
    ("auth-boundary", ["auth boundary", "401", "403"]),
    ("exposed-path", ["sensitive path", ".git", ".env", "info.php",
                      "directory listing", "backup"]),
    ("secret-leak", ["secret in", "api key", "token in"]),
    ("cors", ["cors"]),
    ("takeover", ["takeover"]),
    ("version-cve", ["version disclosed", "cve surface", "known vulnerability"]),
    ("weak-headers", ["security headers", "missing/weak"]),
]

_PAID = {"paid", "resolved"}
_VALID_OUTCOME = {"triaged", "valid", "accepted", "duplicate"}
_WASTED_OUTCOME = {"n-a", "not-applicable", "na", "informative", "spam", "invalid"}

# Points per outcome class — paid rewarded most, wasted penalized (all 3 goals).
_POINTS = {"paid": 3.0, "valid": 1.0, "wasted": -1.5, "pending": 0.0}

# How hard the learned signal nudges the base priority score.
_NUDGE = 3.0


def signal_type(signal: str) -> str:
    low = signal.lower()
    for name, keywords in _SIGNAL_TYPES:
        if any(k in low for k in keywords):
            return name
    return "other"


def outcome_class(record) -> str:
    """paid / valid / wasted / pending for one finding, from status + outcome."""
    outcome = (getattr(record, "outcome", "") or "").lower()
    status = (getattr(record, "status", "") or "").lower()
    bounty = getattr(record, "bounty", 0) or 0
    if outcome in _PAID or bounty > 0:
        return "paid"
    if status == "real" or outcome in _VALID_OUTCOME:
        return "valid"
    if status == "false" or outcome in _WASTED_OUTCOME:
        return "wasted"
    return "pending"


def signal_weights(records) -> dict[str, float]:
    """Per signal-type multiplier learned from history; empty until there's data.

    Findings without a verdict yet (``pending``) don't vote.
    """
    votes: dict[str, list[float]] = {}
    for record in records:
        cls = outcome_class(record)
        if cls == "pending":
            continue
        for signal in getattr(record, "signals", None) or []:
            votes.setdefault(signal_type(signal), []).append(_POINTS[cls])
    return {t: round(sum(p) / len(p), 3) for t, p in votes.items() if p}


def learned_score(record, weights: dict[str, float]) -> float:
    """Base priority nudged by what its signal types have historically been worth."""
    base = float(getattr(record, "priority_score", 0) or 0)
    bonus = sum(weights.get(signal_type(s), 0.0)
                for s in (getattr(record, "signals", None) or []))
    return base + _NUDGE * bonus


def summarize(records) -> dict:
    """Aggregate outcomes per signal-type and per program, for the lessons file."""
    by_signal: dict[str, dict] = {}
    by_program: dict[str, dict] = {}
    total_bounty = 0.0

    def _bucket(store: dict, key: str) -> dict:
        return store.setdefault(
            key, {"paid": 0, "valid": 0, "wasted": 0, "pending": 0, "bounty": 0.0})

    for record in records:
        cls = outcome_class(record)
        bounty = float(getattr(record, "bounty", 0) or 0)
        total_bounty += bounty
        prog = _bucket(by_program, getattr(record, "program", "?"))
        prog[cls] += 1
        prog["bounty"] += bounty
        for signal in getattr(record, "signals", None) or []:
            sig = _bucket(by_signal, signal_type(signal))
            sig[cls] += 1
            sig["bounty"] += bounty

    return {"by_signal": by_signal, "by_program": by_program,
            "total_bounty": round(total_bounty, 2)}
