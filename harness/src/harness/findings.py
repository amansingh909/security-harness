"""Scaffold a bounty-reporter finding file from a recon lead.

Crucially this produces a *template* with TODO placeholders for the evidence
only manual testing can supply (repro steps, observed result, impact). It never
invents those — that's the same non-fabrication rule bounty-reporter enforces,
and it's why the reporter will refuse the file until you fill the TODOs in."""
from __future__ import annotations

import yaml


def finding_template(program: str, lead: dict) -> str:
    """Return a YAML finding stub pre-filled with known facts + TODO markers."""
    host = lead.get("host", "")
    url = lead.get("url") or f"https://{host}"
    cve_refs = [
        f"https://nvd.nist.gov/vuln/detail/{c['cve_id']}"
        for c in lead.get("cve_candidates", [])
        if c.get("cve_id")
    ]
    signals = lead.get("signals", [])

    stub = {
        "program": program,
        "vuln_type": "TODO — e.g. IDOR, Broken Access Control, Info Disclosure",
        "asset": url,
        "affected_param": "TODO — the parameter/ID you tampered with (or remove)",
        "cwe": "TODO — e.g. CWE-639 for IDOR (or remove)",
        "cvss_vector": "TODO — e.g. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (or remove)",
        "summary": "TODO — 2-3 sentences: what the bug is, where, why it matters",
        "steps_to_reproduce": [
            "TODO — start from a clean state (e.g. log in as User A)",
            "TODO — the exact action / request",
            "TODO — observe the result that proves the bug",
        ],
        "observed_result": "TODO — what proved it (the response / data returned)",
        "impact": "TODO — what an attacker can actually do, at what scale",
        "remediation": "TODO — the specific fix (or remove)",
        "references": cve_refs,
        "_recon_context": {
            "why_flagged": signals,
            "status": lead.get("status"),
            "fingerprints": [
                f"{f.get('product')} {f.get('version') or ''}".strip()
                for f in lead.get("fingerprints", [])
            ],
            "note": "Filled by recon; verify by hand before submitting.",
        },
    }
    header = (
        f"# Finding scaffold for {host} (program: {program})\n"
        "# Fill every TODO from your OWN manual testing. bounty-reporter will\n"
        "# refuse this file until the required evidence fields are real.\n"
        "# Delete the _recon_context block before submitting.\n"
    )
    return header + yaml.safe_dump(stub, sort_keys=False, allow_unicode=True)


_REQUIRED = ("vuln_type", "asset", "observed_result", "impact")


def unfilled_todos(data: dict) -> list[str]:
    """Which required fields still hold their TODO placeholder. A filled asset
    is exempt (the scaffold pre-fills it with the real host)."""
    todos: list[str] = []
    for field in _REQUIRED:
        value = data.get(field, "")
        if isinstance(value, str) and value.strip().upper().startswith("TODO"):
            todos.append(field)
    steps = data.get("steps_to_reproduce") or []
    if steps and all(
        isinstance(s, str) and s.strip().upper().startswith("TODO") for s in steps
    ):
        todos.append("steps_to_reproduce")
    return todos
