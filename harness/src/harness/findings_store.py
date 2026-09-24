"""Per-finding records the operator reviews and marks — one file per finding.

Unlike ``leads.json`` / ``vulns.json`` (whole-file blobs rewritten on every
scan), a finding here is its own small file carrying a mutable ``status``. That
lets the autonomous runner refresh the machine-derived fields on each run
WITHOUT erasing a verdict the operator already gave the finding. This store is
what the TUI Findings screen reads and writes.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from .store import _program_dir

# Machine-assigned: ``ready`` = observation-confirmed, ``needs_check`` = needs a
# manual active test. Operator-assigned: ``real`` / ``false`` / ``duplicate``.
FindingStatus = Literal["ready", "needs_check", "real", "false", "duplicate"]
_OPERATOR_STATUSES = {"real", "false", "duplicate"}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


class FindingRecord(BaseModel):
    id: str
    program: str
    host: str = ""
    url: str = ""
    service: dict = Field(default_factory=dict)
    signals: list[str] = Field(default_factory=list)      # what recon actually found
    fingerprints: list[dict] = Field(default_factory=list)
    cves: list[dict] = Field(default_factory=list)
    priority_score: int = 0
    status: FindingStatus = "needs_check"
    note: str = ""
    created_at: str = Field(default_factory=_now)
    updated_at: str = Field(default_factory=_now)


def finding_id(program: str, host: str, port) -> str:
    """Stable id for a finding so a re-scan updates it in place, not duplicates."""
    return hashlib.sha1(f"{program}|{host}|{port}".encode()).hexdigest()[:12]


def record_from_vuln(program: str, vuln: dict) -> FindingRecord:
    """Build a fresh (machine-status) record from a ``scan_for_vulns`` dict."""
    service = vuln.get("service") or {}
    host = vuln.get("host") or service.get("host", "")
    port = service.get("port", "")
    return FindingRecord(
        id=finding_id(program, host, port),
        program=program,
        host=host,
        service=service,
        cves=vuln.get("cves", []),
        priority_score=vuln.get("priority_score", 0),
        status="needs_check",
    )


def record_from_lead(program: str, lead: dict) -> FindingRecord:
    """Build a record from a recon lead — where the real findings (signals) live.

    A lead carries the signals recon actually observed (reflected XSS, exposed
    paths, version disclosure) plus fingerprints and any CVE candidates. This is
    the review-queue source; the id is stable per host so a re-run updates in
    place.
    """
    host = lead.get("host", "")
    return FindingRecord(
        id=finding_id(program, host, ""),
        program=program,
        host=host,
        url=lead.get("url", ""),
        service={"host": host, "url": lead.get("url", ""),
                 "status_code": lead.get("status")},
        signals=lead.get("signals", []),
        fingerprints=lead.get("fingerprints", []),
        cves=lead.get("cve_candidates", []),
        priority_score=lead.get("priority_score", 0),
        status="needs_check",
    )


def _findings_dir(program: str) -> Path:
    return _program_dir(program) / "findings"


def _finding_path(program: str, fid: str) -> Path:
    return _findings_dir(program) / f"{fid}.json"


def save_finding(record: FindingRecord) -> Path:
    path = _finding_path(record.program, record.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(record.model_dump_json(indent=2), encoding="utf-8")
    return path


def get_finding(program: str, fid: str) -> FindingRecord | None:
    path = _finding_path(program, fid)
    if not path.exists():
        return None
    return FindingRecord.model_validate_json(path.read_text(encoding="utf-8"))


def load_findings(program: str) -> list[FindingRecord]:
    directory = _findings_dir(program)
    if not directory.exists():
        return []
    out: list[FindingRecord] = []
    for path in sorted(directory.glob("*.json")):
        try:
            out.append(
                FindingRecord.model_validate_json(path.read_text(encoding="utf-8"))
            )
        except (json.JSONDecodeError, ValueError):
            # A corrupt finding file must not sink the whole review queue.
            continue
    return out


def update_status(
    program: str, fid: str, status: FindingStatus, note: str | None = None
) -> FindingRecord | None:
    """Set a finding's status (and optionally its note); returns the saved record."""
    record = get_finding(program, fid)
    if record is None:
        return None
    record.status = status
    if note is not None:
        record.note = note
    record.updated_at = _now()
    save_finding(record)
    return record


def upsert_findings(program: str, records: list[FindingRecord]) -> int:
    """Persist scan records, preserving any operator verdict already on file.

    A re-scan re-derives host / service / cves, but when the operator has
    already marked a finding ``real`` / ``false`` / ``duplicate`` we keep that
    verdict and their note, so a nightly run never erases a review. Returns the
    number of records written.
    """
    for record in records:
        existing = get_finding(program, record.id)
        if existing is not None:
            record.created_at = existing.created_at
            if existing.status in _OPERATOR_STATUSES:
                record.status = existing.status
                record.note = existing.note
        record.updated_at = _now()
        save_finding(record)
    return len(records)
