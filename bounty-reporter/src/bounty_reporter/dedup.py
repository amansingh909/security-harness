"""Duplicate-finding fingerprinting.

Two findings are 'the same bug' when they hit the same program, the same
vulnerability class, and the same asset location (host + path + parameter).
Query strings and schemes are ignored so ``?id=1`` and ``?id=2`` collapse."""
from __future__ import annotations

import hashlib
from urllib.parse import urlparse

from .models import Finding


def _normalize_asset(asset: str) -> tuple[str, str]:
    parsed = urlparse(asset if "//" in asset else f"//{asset}")
    host = (parsed.netloc or parsed.path.split("/")[0]).lower()
    path = parsed.path if parsed.netloc else "/".join(parsed.path.split("/")[1:])
    # Collapse resource-id-shaped path segments so /invoices/1 and /invoices/2
    # (the same IDOR bug) fingerprint identically. Pure-digit segments and the
    # literal {id}-style template placeholders both normalize to {n}.
    segments = []
    for seg in path.strip("/").split("/"):
        if seg.isdigit() or (seg.startswith("{") and seg.endswith("}")):
            segments.append("{n}")
        else:
            segments.append(seg)
    return host, "/" + "/".join(segments)


def fingerprint(finding: Finding) -> str:
    host, path = _normalize_asset(finding.asset)
    parts = [
        finding.program.strip().lower(),
        finding.vuln_type.strip().lower(),
        host,
        path,
        (finding.affected_param or "").strip().lower(),
    ]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Return findings with duplicates (same fingerprint) removed, first wins."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        fp = fingerprint(finding)
        if fp not in seen:
            seen.add(fp)
            unique.append(finding)
    return unique
