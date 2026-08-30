# Unit tests for crt.sh subdomain enumeration.
# No network involved — we mock the HTML response. Pure parsing + validation logic
# is tested.
import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from recon_orchestrator.subdomain_enum.fetch_crtsh import (
    normalize_subdomain,
    _parse_crtsh_page,
    fetch_crtsh_for_apex,
)


def test_normalize_subdomain_ok():
    ok_cases = [
        "www.example.com",
        "api.example.com",
        "staging.example.com",
        "dev-api.example.com",
    ]
    for s in ok_cases:
        assert normalize_subdomain(s) == s.lower()


def test_normalize_subdomain_malformed():
    bad_cases = [
        "",
        "*",
        "*.example.com",  # wildcard
        "bad..example.com",
        "bad",
        "example..com",
        "bad-example_",  # underscore in label (technically valid but rare)
    ]
    for s in bad_cases:
        assert normalize_subdomain(s) is None


def test_normalize_subdomain_trailing_dot():
    assert normalize_subdomain("www.example.com.") == "www.example.com"


def test_parse_crtsh_page_happy():
    html = """
    <html>
    <tr>- <www.example.com><br></tr>
    <tr>- <api.example.com><br></tr>
    </html>
    """
    names = _parse_crtsh_page(html, "example.com")
    assert names == {"www.example.com", "api.example.com"}


def test_parse_crtsh_page_mixed_content():
    html = """
    <tr>- <admin.example.com><br>admin@example.com</tr>
    <tr>- <staging.example.com><br>...</tr>
    <tr>- <*.evil.com> not relevant</tr>
    """
    names = _parse_crtsh_page(html, "example.com")
    assert names == {"admin.example.com", "staging.example.com"}


@pytest.mark.asyncio
async def test_fetch_crtsh_for_apex_with_real_response():
    mock_html = """
    <html>
    <tr>- <jenkins.example.com><br></tr>
    <tr>- <dev.example.com><br></tr>
    </html>
    """
    # Mock the httpx.AsyncClient context manager
    mock_session = AsyncMock()
    mock_response = AsyncMock()
    mock_response.text = mock_html
    mock_response.raise_for_status = AsyncMock()
    mock_session.get.return_value = mock_response

    with patch("recon_orchestrator.subdomain_enum.fetch_crtsh.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value = mock_session

        apex = "example.com"
        names = await fetch_crtsh_for_apex(apex)

    assert names == {"jenkins.example.com", "dev.example.com"}


@pytest.mark.asyncio
async def test_fetch_crtsh_for_apex_network_failure(monkeypatch):
    import httpx

    # Create a mock session whose get method raises an HTTPError
    mock_session = AsyncMock()
    mock_session.get.side_effect = httpx.HTTPError("network down")

    with patch("recon_orchestrator.subdomain_enum.fetch_crtsh.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value = mock_session

        apex = "example.com"
        names = await fetch_crtsh_for_apex(apex)

    assert names == set()


@pytest.mark.asyncio
async def test_fetch_crtsh_for_apex_timeout(monkeypatch):
    import httpx

    # Create a mock session whose get method raises a timeout error
    mock_session = AsyncMock()
    mock_session.get.side_effect = httpx.TimeoutException("request timed out")

    with patch("recon_orchestrator.subdomain_enum.fetch_crtsh.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value = mock_session

        apex = "example.com"
        names = await fetch_crtsh_for_apex(apex)

    assert names == set()