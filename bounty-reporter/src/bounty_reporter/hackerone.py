"""Serialize a Finding into a HackerOne report-submission payload (JSON:API)."""
from __future__ import annotations

from .models import Finding
from .vrt import hackerone_weakness

# HackerOne severity_rating accepts these lowercase bands.
_RATING_TO_H1 = {
    "NONE": "none",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}


def to_submission(
    finding: Finding,
    markdown: str,
    rating: str,
    cvss_score: float | None,
    cwe: str | None,
) -> dict:
    attributes: dict = {
        "team_handle": finding.program,
        "title": finding.resolved_title(),
        "vulnerability_information": markdown,
        "impact": finding.impact,
        "severity_rating": _RATING_TO_H1.get(rating.upper(), "none"),
        "weakness": hackerone_weakness(cwe),
    }
    if finding.cvss_vector and cvss_score is not None:
        attributes["severity"] = {
            "rating": _RATING_TO_H1.get(rating.upper(), "none"),
            "score": cvss_score,
            "vector_string": finding.cvss_vector,
        }
    return {"data": {"type": "report", "attributes": attributes}}
