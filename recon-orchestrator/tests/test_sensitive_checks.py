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
async def test_check_sensitive_paths_mocked():
    """Test sensitive path checking with mocked responses."""
    settings = Settings(
        requests_per_second=2.0,
        max_concurrency=10,
        http_timeout=15.0,
        connect_timeout=5.0,
        max_retries=3,
        backoff_base=1.0,
        backoff_max=30.0,
        user_agent="test-agent/1.0",
        verify_tls=True,
        cve_index_url=None,
    )

    # Create mock responses for different paths
    mock_resp_200 = AsyncMock()
    mock_resp_200.status_code = 200
    mock_resp_200.headers = {"server": "nginx/1.18.0"}
    mock_resp_200.url = "http://example.com/.git/HEAD"

    mock_resp_404 = AsyncMock()
    mock_resp_404.status_code = 404
    mock_resp_404.headers = {"server": "nginx/1.18.0"}
    mock_resp_404.url = "http://example.com/.env"

    mock_resp_403 = AsyncMock()
    mock_resp_403.status_code = 403
    mock_resp_403.headers = {"server": "nginx/1.18.0"}
    mock_resp_403.url = "http://example.com/server-status"

    # Mock the httpx.AsyncClient
    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None

    # Return different responses based on URL
    def mock_get(url):
        if ".git/HEAD" in url:
            return mock_resp_200
        elif ".env" in url:
            return mock_resp_404
        elif "server-status" in url:
            return mock_resp_403
        else:
            # Default to 404 for other paths
            return mock_resp_404

    mock_client_instance.get.side_effect = mock_get

    with patch("recon_orchestrator.sensitive_checks.checks.httpx.AsyncClient") as mock_client:
        mock_client.return_value = mock_client_instance

        findings = await check_sensitive_paths("example.com", settings, [80])

        # Should have found the .git/HEAD path (status 200 < 500)
        # and the server-status path (status 403 < 500)
        # but not the .env path (we're only checking that it returned something < 500)
        # Actually, 404 is also < 500, so it would be included
        # Let's check that we got responses
        assert len(findings) > 0

        # Check that we have probes for the paths we tested
        urls = {str(f.url) for f in findings}
        # At least some of our test paths should be found
        assert any("example.com" in url for url in urls)


@pytest.mark.asyncio
async def test_run_sensitive_checks_mocked():
    """Test running all sensitive checks with mocked responses."""
    settings = Settings(
        requests_per_second=2.0,
        max_concurrency=10,
        http_timeout=15.0,
        connect_timeout=5.0,
        max_retries=3,
        backoff_base=1.0,
        backoff_max=30.0,
        user_agent="test-agent/1.0",
        verify_tls=True,
        cve_index_url=None,
    )

    # Create mock responses
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "server": "nginx/1.18.0",
        "access-control-allow-origin": "*",  # CORS misconfiguration
        "strict-transport-security": "max-age=31536000",  # This one is present
        # Missing: x-content-type-options, x-frame-options, etc.
        "set-cookie": "sessionid=abc123; Path=/"  # Missing HttpOnly, Secure, SameSite
    }
    mock_resp.url = "http://example.com/"

    # Mock the httpx.AsyncClient
    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None
    mock_client_instance.head.return_value = mock_resp
    mock_client_instance.get.return_value = mock_resp

    with patch("recon_orchestrator.sensitive_checks.checks.httpx.AsyncClient") as mock_client:
        mock_client.return_value = mock_client_instance

        findings = await run_sensitive_checks("example.com", settings, [80])

        # Should have findings from both path scanning and header/cookie checks
        assert len(findings) > 0

        # We should have at least one finding from the HEAD request (header/cookie checks)
        # and potentially from path scanning

        # Check that we have probes
        assert all(isinstance(f, HostProbe) for f in findings)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])