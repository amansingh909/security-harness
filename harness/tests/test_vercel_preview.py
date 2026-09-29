"""Tests for the Vercel preview target resolver.

Active testing must land on a preview deployment you own, never prod — so the
resolver returns one exact host, and the API path excludes production.
"""
from __future__ import annotations

import httpx
import pytest

from harness.vercel import host_from_url, latest_preview_host


@pytest.mark.parametrize("value,expected", [
    ("https://trazo-git-main-aman.vercel.app", "trazo-git-main-aman.vercel.app"),
    ("trazo-abc123.vercel.app", "trazo-abc123.vercel.app"),
    ("https://trazo-xyz.vercel.app/dash?x=1", "trazo-xyz.vercel.app"),
    ("HTTPS://Trazo-XYZ.vercel.app", "trazo-xyz.vercel.app"),
])
def test_host_from_url(value, expected):
    assert host_from_url(value) == expected


@pytest.mark.parametrize("value", ["", "not a url", "trazo", "   "])
def test_host_from_url_rejects_non_hosts(value):
    assert host_from_url(value) is None


@pytest.mark.asyncio
async def test_latest_preview_host_picks_newest_ready_preview(monkeypatch):
    payload = {"deployments": [
        {"url": "trazo-new-preview.vercel.app", "state": "READY", "target": None},
        {"url": "trazo-old-preview.vercel.app", "state": "READY", "target": None},
        {"url": "trazo-prod.vercel.app", "state": "READY", "target": "production"},
    ]}

    def handler(request):
        assert request.headers["Authorization"] == "Bearer tok"
        return httpx.Response(200, json=payload)

    async def fake_get(self, url, headers=None, params=None):
        return handler(httpx.Request("GET", url, headers=headers))
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    host = await latest_preview_host("trazo", "tok")
    assert host == "trazo-new-preview.vercel.app"   # newest, and not production


@pytest.mark.asyncio
async def test_latest_preview_host_excludes_production(monkeypatch):
    payload = {"deployments": [
        {"url": "trazo-prod.vercel.app", "state": "READY", "target": "production"},
    ]}

    async def fake_get(self, url, headers=None, params=None):
        return httpx.Response(200, json=payload)
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    with pytest.raises(LookupError):
        await latest_preview_host("trazo", "tok")


@pytest.mark.asyncio
async def test_bad_token_raises_permission_error(monkeypatch):
    async def fake_get(self, url, headers=None, params=None):
        return httpx.Response(401, text="unauthorized")
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    with pytest.raises(PermissionError):
        await latest_preview_host("trazo", "bad")
