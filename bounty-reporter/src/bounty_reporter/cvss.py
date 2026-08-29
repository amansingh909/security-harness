"""CVSS v3.1 base-score calculator and vector parser (pure, spec-accurate).

Implements the equations from the FIRST CVSS v3.1 specification, including the
exact 'roundup' function. No external dependencies so it is fully unit-tested.
"""
from __future__ import annotations

import math

# --- metric weights (CVSS v3.1 spec, section 7.4) -----------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


class CvssError(ValueError):
    """Raised for malformed or incomplete CVSS vectors."""


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a ``CVSS:3.1/AV:N/...`` string into a metric->value dict.

    Validates the version prefix and that all 8 base metrics are present with
    legal values. Temporal/environmental metrics are ignored if present.
    """
    if not vector or not isinstance(vector, str):
        raise CvssError("empty CVSS vector")
    parts = vector.strip().split("/")
    if not parts or parts[0].upper() not in ("CVSS:3.1", "CVSS:3.0"):
        raise CvssError(f"unsupported CVSS version prefix: {parts[0]!r}")
    metrics: dict[str, str] = {}
    for token in parts[1:]:
        if ":" not in token:
            raise CvssError(f"malformed metric token: {token!r}")
        key, value = token.split(":", 1)
        metrics[key.upper()] = value.upper()
    missing = [m for m in _BASE_METRICS if m not in metrics]
    if missing:
        raise CvssError(f"missing base metrics: {missing}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: round up to one decimal, with the spec's integer
    trick to avoid binary float artifacts."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a vector string."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    try:
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise CvssError(f"illegal metric value: {exc}") from exc

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def qualitative_rating(score: float) -> str:
    """Map a base score to the CVSS qualitative severity band."""
    if score <= 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
