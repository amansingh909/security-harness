from bounty_reporter.generator import generate
from bounty_reporter.models import Finding


def _finding(**over):
    base = dict(
        program="acme", vuln_type="IDOR",
        asset="https://app.example.com/api/v2/invoices/{id}",
        affected_param="id", cwe="CWE-639",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        summary="Invoice endpoint lacks ownership check.",
        steps_to_reproduce=["register two accounts", "swap the id", "read victim invoice"],
        observed_result="victim invoice returned in full",
        impact="any user reads any invoice; sequential ids enumerate the table",
        remediation="enforce ownership check; 404 on non-owned ids",
    )
    base.update(over)
    return Finding(**base)


def test_generate_computes_cvss_and_rating():
    report = generate(_finding())
    assert report.cvss_score == 6.5
    assert report.rating == "MEDIUM"
    assert report.cwe == "CWE-639"
    assert len(report.fingerprint) == 16


def test_markdown_has_all_sections():
    md = generate(_finding()).markdown
    for section in ("# IDOR on", "## Steps to Reproduce", "## Impact",
                    "## Severity", "## Classification", "## Remediation"):
        assert section in md
    assert "6.5" in md and "CWE-639" in md


def test_hackerone_payload_shape():
    h1 = generate(_finding()).hackerone
    attrs = h1["data"]["attributes"]
    assert h1["data"]["type"] == "report"
    assert attrs["team_handle"] == "acme"
    assert attrs["severity_rating"] == "medium"
    assert attrs["severity"]["score"] == 6.5
    assert attrs["weakness"] == "Insecure Direct Object Reference (IDOR)"


def test_bugcrowd_payload_shape():
    bc = generate(_finding()).bugcrowd
    attrs = bc["data"]["attributes"]
    assert attrs["vrt_id"] == "broken_access_control.idor"
    assert attrs["priority"] == 3  # MEDIUM -> P3


def test_invalid_cvss_leaves_unrated_not_crash():
    report = generate(_finding(cvss_vector="not-a-vector"))
    assert report.cvss_score is None
    assert report.rating == "UNRATED"
    assert "Unrated pending a CVSS vector" in report.markdown


def test_no_vector_is_unrated():
    report = generate(_finding(cvss_vector=None))
    assert report.rating == "UNRATED"
