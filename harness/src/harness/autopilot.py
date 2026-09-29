"""Autopilot: turn a CONFIRMED active-test finding into a ready-to-review draft
report, saved to a per-program playbook.

For programs you have armed for active testing (`mode=practice`), which includes
your own authorized real assets, the active engine sends a unique probe and
confirms a hit (a marker reflected unencoded, or a database error provoked).
Autopilot drafts a report from that, honestly: the request it documents is the
exact one the engine sent (the discovered endpoint and parameter plus the known
probe payload), and the observed result is the true detection. Nothing is
invented.

It never submits, and it only drafts findings from programs armed for active
testing. A `mode=real` (passive, third-party bug-bounty) program is left
untouched. Confirming and submitting stay with the human.
"""
from __future__ import annotations

import re

from .store import _program_dir

# The active engine writes each hit as: "<desc> at <path> via '<param>'".
_SIGNAL_RE = re.compile(r"^(?P<desc>.+?) at (?P<path>\S+) via '(?P<param>[^']+)'$")


def _payload_for(kind: str) -> str:
    """The exact probe payload the active engine sends, read from recon's vectors
    so it stays in sync rather than being copied."""
    try:
        from recon_orchestrator import payloads
    except ImportError:  # pragma: no cover - env dependent
        return ""
    for test in payloads.TESTS:
        if test.kind == kind:
            return test.value
    return ""


def _base_of(record) -> str:
    """scheme://host for the finding, to rebuild the exact request URL."""
    from urllib.parse import urlsplit, urlunsplit

    url = getattr(record, "url", None) or (
        f"https://{record.host}" if getattr(record, "host", "") else ""
    )
    if not url:
        return ""
    p = urlsplit(url)
    return urlunsplit((p.scheme or "https", p.netloc or record.host, "", "", ""))


def evidence_from_signal(record, signal: str) -> dict | None:
    """Build a draft-ready, non-fabricated finding dict from ONE confirmed
    active-test signal, or None if the signal is not an active-test hit.

    Every field is a true statement about what the engine did: the request URL
    is the exact probe it sent, and the observed result is the detection that
    fired.
    """
    m = _SIGNAL_RE.match((signal or "").strip())
    if not m:
        return None
    desc, path, param = m["desc"], m["path"], m["param"]
    low = desc.lower()
    base = _base_of(record)
    asset = base or getattr(record, "host", "") or ""

    if "reflect" in low or "xss" in low:
        payload = _payload_for("reflection")
        url = f"{base}{path}?{param}={payload}"
        return {
            "vuln_type": "Reflected XSS",
            "asset": asset,
            "affected_param": param,
            "summary": f"Reflected XSS in the '{param}' parameter at {path}.",
            "steps_to_reproduce": [f"Send: GET {url}"],
            "observed_result": (
                f"The unique probe marker '{payload}' was returned unencoded in the "
                f"response body, confirming '{param}' is reflected without sanitization."
            ),
            "impact": (
                "An attacker can inject HTML/JavaScript that runs in a victim's "
                "browser in the site's origin, enabling session theft, credential "
                "capture, or actions taken as the victim."
            ),
        }

    if "sql" in low:
        payload = _payload_for("sql_error")
        url = f"{base}{path}?{param}={payload}"
        return {
            "vuln_type": "SQL Injection (error-based)",
            "asset": asset,
            "affected_param": param,
            "summary": f"Error-based SQL injection in the '{param}' parameter at {path}.",
            "steps_to_reproduce": [f"Send: GET {url}"],
            "observed_result": (
                "The response returned a database error signature after the payload "
                f"was injected into '{param}', indicating the input reaches a SQL "
                "query without proper parameterization."
            ),
            "impact": (
                "An attacker may read or modify database contents, bypass "
                "authentication, or escalate further depending on the backend."
            ),
        }

    return None


def drafts_for(record) -> list[dict]:
    """Every confirmed active-test evidence dict for a finding (one per hit)."""
    out: list[dict] = []
    seen: set[tuple] = set()
    for sig in getattr(record, "signals", None) or []:
        ev = evidence_from_signal(record, sig)
        if ev:
            key = (ev["vuln_type"], ev["asset"], ev["affected_param"])
            if key not in seen:
                seen.add(key)
                out.append(ev)
    return out


def playbook_dir(program: str):
    """Per-program directory that holds autopilot's ready drafts."""
    d = _program_dir(program) / "playbook"
    d.mkdir(parents=True, exist_ok=True)
    return d
