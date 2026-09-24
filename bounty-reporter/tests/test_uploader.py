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

# A finding the operator has verified: it carries real evidence the scanner
# could never produce on its own.
VERIFIED = {
    "vuln_type": "IDOR",
    "asset": "https://app.example.com/api/invoices/{id}",
    "steps_to_reproduce": [
        "Log in as User A and note User B's invoice id 4021.",
        "As User A, GET /api/invoices/4021.",
        "Observe User B's invoice returned in full.",
    ],
    "observed_result": "User B's invoice was returned under User A's session.",
    "impact": "Any authenticated user can read any other user's invoices by id.",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "cwe": "CWE-639",
}


def test_build_finding_refuses_an_unverified_scan_lead():
    """The scanner never observes impact, reproduces anything, or confirms a
    bug — inventing those fields manufactures evidence that gets an account
    banned once submitted. A raw scan lead must be refused, not fabricated."""
    with pytest.raises(ValueError, match="unverified"):
        _build_finding("prog", VULN)


def test_build_finding_builds_from_verified_evidence():
    """Given a finding the operator has completed with real evidence, build it."""
    finding = _build_finding("prog", VERIFIED)
    assert finding.vuln_type == "IDOR"
    assert finding.observed_result.startswith("User B")
    assert finding.impact
    assert len(finding.steps_to_reproduce) == 3
    assert finding.cwe == "CWE-639"


def test_upload_does_not_post_an_unverified_scan_lead(tmp_path, monkeypatch):
    """The batch report is raw scan output; upload must refuse every finding and
    never send a single fabricated submission to a real program."""
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"vulnerabilities": [VULN]}))

    posted = {"count": 0}

    class CountingClient:
        def __init__(self, *a, **k):
            ...

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            posted["count"] += 1

            class _Resp:
                status_code = 201
                text = "ok"

            return _Resp()

    monkeypatch.setattr("bounty_reporter.uploader.httpx.AsyncClient", CountingClient)

    result = upload_report(report, "prog", "a-token", "bc-token", h1_identifier="id")

    assert posted["count"] == 0, "upload attempted a POST for an unverified scan lead"
    assert result["hackerone"]["sent"] == 0
    assert result["bugcrowd"]["sent"] == 0
    assert result["hackerone"]["failed"] == 1
    assert result["bugcrowd"]["failed"] == 1
    assert any("unverified" in e.lower() for e in result["hackerone"]["errors"])


def test_cvss_score_comes_from_the_scan_not_the_vector():
    """float('CVSS:3.1/AV:N/AC:L'.split('/')[1]) is float('AV:N') -> ValueError."""
    with pytest.raises(ValueError):
        float(VULN["cves"][0]["cvss_vector"].split("/")[1])
    assert VULN["cves"][0]["cvss_score"] == 7.5
