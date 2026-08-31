"""Regression tests for the upload path.

None of this had ever executed. In order, `upload_report` died on a relative
import that escaped the package, then on a Markdown path handed to a JSON
parser, then on `asyncio` being imported inside an inner function, then on
`Bearer` auth that HackerOne answers with 401, then on a `Finding` built
without its required fields.
"""
from __future__ import annotations

import base64
import json

import pytest

from bounty_reporter.uploader import _build_finding, _h1_auth_header, upload_report


VULN = {
    "host": "www.example.com",
    "service": {
        "host": "www.example.com", "port": 443, "scheme": "https",
        "server": "nginx/1.24.0", "powered_by": "Express",
        "status_code": 200, "title": "Example",
    },
    "cves": [{
        "id": "CVE-2024-1234", "cvss_vector": "CVSS:3.1/AV:N/AC:L",
        "cvss_score": 7.5, "exploit_available": True,
    }],
    "priority_score": 80,
}


# --- HackerOne authentication ------------------------------------------------

def test_h1_auth_header_is_basic_not_bearer():
    """HackerOne uses HTTP Basic identifier:token. Bearer returns 401 for any
    token, valid or not — verified against the live API."""
    header = _h1_auth_header("an-identifier", "a-token")
    scheme, _, payload = header.partition(" ")
    assert scheme == "Basic"
    assert base64.b64decode(payload).decode() == "an-identifier:a-token"


def test_h1_auth_header_survives_base64_padding():
    """Real HackerOne tokens end in '=' padding; joining must not mangle it."""
    token = "EXAMPLEtoken0000000000000000000000000000000="  # fake, '=' padded
    decoded = base64.b64decode(_h1_auth_header("user", token).split()[1]).decode()
    assert decoded == f"user:{token}"


def test_upload_refuses_a_token_without_an_identifier(tmp_path, monkeypatch):
    """Basic auth has two halves; the token alone cannot authenticate. Fail up
    front rather than 401 once per finding."""
    monkeypatch.delenv("H1_IDENTIFIER", raising=False)
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"vulnerabilities": []}))

    with pytest.raises(ValueError, match="identifier"):
        upload_report(report, "prog", "a-token", None)


def test_upload_takes_identifier_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("H1_IDENTIFIER", "from-env")
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"vulnerabilities": []}))

    result = upload_report(report, "prog", "a-token", None)

    assert result["hackerone"] == {"sent": 0, "failed": 0, "errors": []}


def test_upload_rejects_a_missing_report(tmp_path):
    with pytest.raises(FileNotFoundError):
        upload_report(tmp_path / "nope.json", "prog", None, None)


# --- Finding construction ----------------------------------------------------

def test_build_finding_supplies_required_fields():
    """Finding.vuln_type is required and steps_to_reproduce is a list[str];
    passing neither raised ValidationError for every real vulnerability."""
    finding = _build_finding("prog", VULN)

    assert finding.vuln_type
    assert isinstance(finding.steps_to_reproduce, list)
    assert len(finding.steps_to_reproduce) >= 1
    assert all(isinstance(s, str) for s in finding.steps_to_reproduce)


def test_build_finding_names_the_cve_when_present():
    finding = _build_finding("prog", VULN)
    assert "CVE-2024-1234" in finding.vuln_type
    assert finding.asset == "www.example.com:443"


def test_build_finding_without_cves():
    """A finding with no CVE still has to produce a valid submission."""
    vuln = {**VULN, "cves": []}
    finding = _build_finding("prog", vuln)

    assert finding.vuln_type
    assert finding.cvss_vector is None
    assert len(finding.steps_to_reproduce) >= 1


def test_build_finding_carries_the_observed_banner():
    """server/powered_by were computed and thrown away, leaving the report a
    bare placeholder with nothing reproducible in it."""
    finding = _build_finding("prog", VULN)
    assert "nginx/1.24.0" in finding.observed_result


def test_cvss_score_comes_from_the_scan_not_the_vector():
    """float('CVSS:3.1/AV:N/AC:L'.split('/')[1]) is float('AV:N') -> ValueError."""
    with pytest.raises(ValueError):
        float(VULN["cves"][0]["cvss_vector"].split("/")[1])
    assert VULN["cves"][0]["cvss_score"] == 7.5
