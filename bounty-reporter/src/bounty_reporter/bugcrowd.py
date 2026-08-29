"""Serialize a Finding into a Bugcrowd submission payload with a VRT id and a
P1-P5 priority derived from the CVSS qualitative rating."""
from __future__ import annotations

from .models import Finding
from .vrt import bugcrowd_vrt

_RATING_TO_PRIORITY = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "NONE": 5,
}


def to_submission(
    finding: Finding,
    markdown: str,
    rating: str,
    cwe: str | None,
) -> dict:
    attributes: dict = {
        "title": finding.resolved_title(),
        "description": markdown,
        "vrt_id": bugcrowd_vrt(cwe),
        "priority": _RATING_TO_PRIORITY.get(rating.upper(), 5),
        "bug_url": finding.asset,
    }
    if finding.poc_request:
        attributes["http_request"] = finding.poc_request
    if finding.cvss_vector:
        attributes["cvss_vector"] = finding.cvss_vector
    return {"data": {"type": "submission", "attributes": attributes}}
