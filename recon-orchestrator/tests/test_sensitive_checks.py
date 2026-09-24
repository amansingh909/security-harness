"""Tests for sensitive checks functionality.

All tests use mocks to avoid actual network calls.
"""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from recon_orchestrator.sensitive_checks.checks import (
    check_cors_misconfiguration,
    check_security_headers,
    check_cookie_flags,
    check_sensitive_paths,
    run_sensitive_checks,
)
from recon_orchestrator.config import Settings
from recon_orchestrator.models import HostProbe


def test_sensitive_checks_carry_extra_request_headers(monkeypatch):
    """A program-required header (e.g. X-Bug-Bounty) must ride the sensitive-path
    client too, not just the shared prober."""
    import recon_orchestrator.sensitive_checks.checks as checks

    captured = {}

    class FakeResp:
        status_code = 404
        text = ""
        headers = {}

    class FakeClient:
        def __init__(self, *a, **k):
            captured["headers"] = k.get("headers")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **k):
            return FakeResp()

        async def head(self, *a, **k):
            return FakeResp()

    monkeypatch.setattr(checks.httpx, "AsyncClient", FakeClient)
    s = Settings(extra_request_headers={"X-Bug-Bounty": "HackerOne-88yk"})
    asyncio.run(checks.check_sensitive_paths("h.example.com", s, ports=[443]))
    assert captured["headers"].get("X-Bug-Bounty") == "HackerOne-88yk"


def test_check_cors_misconfiguration():
    """Test CORS misconfiguration detection."""
    # Test wildcard origin
    headers = {"access-control-allow-origin": "*"}
    issues = check_cors_misconfiguration(headers)
    assert any("Access-Control-Allow-Origin set to '*'" in issue for issue in issues)

    # Test null origin
    headers = {"access-control-allow-origin": "null"}
    issues = check_cors_misconfiguration(headers)
    assert any("Access-Control-Allow-Origin set to 'null'" in issue for issue in issues)

    # Test credentials with wildcard
    headers = {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true"
    }
    issues = check_cors_misconfiguration(headers)
    assert any("Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *" in issue for issue in issues)

    # Test valid configuration (should not flag)
    headers = {
        "access-control-allow-origin": "https://trusted.example.com",
        "access-control-allow-credentials": "true"
    }
    issues = check_cors_misconfiguration(headers)
    assert len(issues) == 0


def test_check_security_headers():
    """Test missing security header detection."""
    # Test with no security headers
    headers = {}
    issues = check_security_headers(headers)
    assert len(issues) == len(["strict-transport-security", "x-content-type-options",
                              "x-frame-options", "x-xss-protection",
                              "content-security-policy", "referrer-policy",
                              "permissions-policy"])

    # Test with some headers present
    headers = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff"
    }
    issues = check_security_headers(headers)
    # Should be missing 5 headers (7 total - 2 present)
    assert len(issues) == 5


def test_check_cookie_flags():
    """Test missing cookie flag detection."""
    # Test cookie missing all flags
    headers = {"set-cookie": "sessionid=abc123; Path=/"}
    issues = check_cookie_flags(headers)
    assert any("Cookie 'sessionid' missing security flags: HttpOnly, Secure, SameSite" in issue
               for issue in issues)

    # Test cookie with some flags
    headers = {"set-cookie": "sessionid=abc123; HttpOnly; Path=/"}
    issues = check_cookie_flags(headers)
    assert any("Cookie 'sessionid' missing security flags: Secure, SameSite" in issue
               for issue in issues)

    # Test cookie with all flags
    headers = {"set-cookie": "sessionid=abc123; HttpOnly; Secure; SameSite=Strict; Path=/"}
    issues = check_cookie_flags(headers)
    assert len(issues) == 0

    # Test multiple cookies (simulating multiple Set-Cookie headers)
    # In reality, multiple Set-Cookie headers come as separate header entries
    # We simulate this by passing a list as the value for the "set-cookie" key
    headers = {
        "set-cookie": [
            "sessionid=abc123; Path=/",
            "prefs=lang=en; HttpOnly; Secure; SameSite=Lax"
        ]
    }
    issues = check_cookie_flags(headers)
    # Should only flag the first cookie (missing all flags)
    assert len(issues) == 1
    assert "Cookie 'sessionid' missing security flags: HttpOnly, Secure, SameSite" in issues[0]


@pytest.mark.asyncio
def _mock_client_returning(by_path):
    """Build a mocked httpx.AsyncClient whose GET returns (status, body) chosen
    by matching a substring of the requested path. follow_redirects is off, so
    the checker sees raw statuses."""
    def mock_get(url, *a, **k):
        status, body = 404, ""
        for needle, (st, bd) in by_path.items():
            if needle in url:
                status, body = st, bd
                break
        resp = AsyncMock()
        resp.status_code = status
        resp.text = body            # a real string, not a coroutine
        resp.headers = {"server": "nginx"}
        resp.url = url
        return resp

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get.side_effect = mock_get
    return client


@pytest.mark.asyncio
async def test_only_content_verified_secrets_are_reported():
    """A 200 that actually serves a .git config is a finding; a 200 that serves
    the SPA's index.html for the same path is not."""
    settings = Settings(user_agent="test/1.0")
    responses = {
        "/.git/config": (200, "[core]\n\trepositoryformatversion = 0\n"),  # real
        "/.env": (200, "<!doctype html><title>App</title>"),               # SPA 200
        "/wp-config.php": (200, "<?php define('DB_PASSWORD','s3cret'); ?>"),  # real
    }
    client = _mock_client_returning(responses)
    with patch("recon_orchestrator.sensitive_checks.checks.httpx.AsyncClient",
               return_value=client):
        findings = await check_sensitive_paths("example.com", settings, [443])

    paths = {f.title for f in findings}
    assert "/.git/config" in paths       # content matched
    assert "/wp-config.php" in paths      # content matched
    assert "/.env" not in paths           # SPA html rejected


@pytest.mark.asyncio
async def test_redirects_and_404s_are_not_findings():
    """A redirect to a login page (307) or a 404 means the file is not there."""
    settings = Settings(user_agent="test/1.0")
    responses = {
        "/.git/config": (307, ""),   # redirect to login
        "/.env": (404, ""),
        "/server-status": (403, "forbidden"),
    }
    client = _mock_client_returning(responses)
    with patch("recon_orchestrator.sensitive_checks.checks.httpx.AsyncClient",
               return_value=client):
        findings = await check_sensitive_paths("example.com", settings, [443])

    assert findings == []


@pytest.mark.asyncio
async def test_run_sensitive_checks_returns_probes_without_error():
    """The aggregator runs without raising and returns a list of HostProbes."""
    settings = Settings(user_agent="test/1.0")
    client = _mock_client_returning({"/.git/config": (200, "[core]\n")})
    with patch("recon_orchestrator.sensitive_checks.checks.httpx.AsyncClient",
               return_value=client):
        findings = await run_sensitive_checks("example.com", settings, [443])
    assert isinstance(findings, list)
    assert all(isinstance(f, HostProbe) for f in findings)
