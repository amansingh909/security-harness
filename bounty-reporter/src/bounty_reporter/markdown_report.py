"""Render a Finding to a triage-ready Markdown report in the report-writer
section order: Title, Summary, Steps, PoC, Impact, Severity, Classification,
Remediation. Only fields present on the Finding are emitted — nothing invented.
"""
from __future__ import annotations

from .models import Finding
from .vrt import hackerone_weakness


def render(
    finding: Finding,
    cvss_score: float | None,
    rating: str,
    cwe: str | None,
) -> str:
    lines: list[str] = []
    lines.append(f"# {finding.resolved_title()}")
    lines.append("")

    if finding.summary:
        lines += ["## Summary", "", finding.summary.strip(), ""]

    lines.append("## Steps to Reproduce")
    lines.append("")
    for i, step in enumerate(finding.steps_to_reproduce, 1):
        lines.append(f"{i}. {step}")
    lines.append("")

    if finding.poc_request or finding.poc_response:
        lines += ["## Proof of Concept", ""]
        if finding.poc_request:
            lines += ["```http", finding.poc_request.strip(), "```", ""]
        if finding.poc_response:
            lines += ["```", finding.poc_response.strip(), "```", ""]
        lines += [
            "_PoC uses only accounts/data controlled by the reporter; "
            "no third-party data was accessed._",
            "",
        ]

    lines += ["## Impact", "", finding.impact.strip(), ""]
    lines += ["**Observed result:** " + finding.observed_result.strip(), ""]

    lines.append("## Severity")
    lines.append("")
    if finding.cvss_vector and cvss_score is not None:
        lines.append(
            f"Suggested: **{rating.title()}** — CVSS v3.1 base **{cvss_score}** "
            f"(`{finding.cvss_vector}`). Computed from the vector; the triager "
            "should weigh the real-world exploitability described above."
        )
    else:
        lines.append(
            "Unrated pending a CVSS vector. Severity should be argued from the "
            "impact above rather than asserted as a number."
        )
    lines.append("")

    lines += ["## Classification", ""]
    if cwe:
        lines.append(f"- **CWE:** {cwe}")
    lines.append(f"- **HackerOne weakness:** {hackerone_weakness(cwe)}")
    lines.append("")

    if finding.remediation:
        lines += ["## Remediation", "", finding.remediation.strip(), ""]

    if finding.references:
        lines += ["## References", ""]
        lines += [f"- {ref}" for ref in finding.references]
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
