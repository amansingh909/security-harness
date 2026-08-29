"""Pydantic models for probe results and candidate leads."""
from __future__ import annotations

from pydantic import BaseModel, Field

# Every candidate carries this so no downstream consumer mistakes a lead for a
# confirmed vulnerability.
UNVERIFIED_NOTE = (
    "Candidate lead only — UNVERIFIED. Manual verification required. "
    "No payloads were sent and no exploitation was attempted."
)


class Fingerprint(BaseModel):
    product: str
    version: str | None = None
    evidence: str  # the header/title text it was derived from


class CveCandidate(BaseModel):
    cve_id: str
    product: str
    version: str | None
    cvss_severity: str | None = None
    cvss_score: float | None = None
    why: str  # e.g. "cve-index match for nginx 1.18.0"


class HostProbe(BaseModel):
    host: str
    url: str | None = None
    status: int | None = None
    title: str | None = None
    server: str | None = None
    port: int = 443
    headers: dict[str, str] = Field(default_factory=dict)
    fingerprints: list[Fingerprint] = Field(default_factory=list)
    error: str | None = None


class CandidateFinding(BaseModel):
    host: str
    url: str | None = None
    priority_score: int
    signals: list[str] = Field(default_factory=list)
    fingerprints: list[Fingerprint] = Field(default_factory=list)
    cve_candidates: list[CveCandidate] = Field(default_factory=list)
    status: int | None = None
    note: str = UNVERIFIED_NOTE
