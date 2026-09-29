"""Tests for the OWASP ZAP active-scan integration.

Mocks ZAP's REST API with an httpx transport, so no real ZAP or target is
touched. Verifies the spider -> active-scan -> alerts flow, the alert-to-signal
mapping, and that the orchestrator scope-gates ZAP's alerts.
"""
from __future__ import annotations

import httpx
import pytest

from recon_orchestrator.config import Settings
from recon_orchestrator.models import HostProbe
from recon_orchestrator.orchestrator import ReconOrchestrator
from recon_orchestrator.scope import ScopeGuard
from recon_orchestrator.zap_client import ZapClient, alerts_to_signals


def _zap_transport(alerts, seen_headers=None):
    """A mock ZAP: scans report done immediately, alerts view returns `alerts`.
    If seen_headers is a list, replacer addRule calls are recorded into it."""
    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p.endswith("/replacer/action/addRule/"):
            if seen_headers is not None:
                seen_headers.append(dict(request.url.params).get("matchString"))
            return httpx.Response(200, json={"Result": "OK"})
        if p.endswith("/replacer/action/removeRule/"):
            return httpx.Response(200, json={"Result": "OK"})
        if p.endswith("/spider/action/scan/"):
            return httpx.Response(200, json={"scan": "0"})
        if p.endswith("/spider/view/status/"):
            return httpx.Response(200, json={"status": "100"})
        if p.endswith("/ascan/action/scan/"):
            return httpx.Response(200, json={"scan": "1"})
        if p.endswith("/ascan/view/status/"):
            return httpx.Response(200, json={"status": "100"})
        if p.endswith("/core/view/alerts/"):
            return httpx.Response(200, json={"alerts": alerts})
        if p.endswith("/core/view/version/"):
            return httpx.Response(200, json={"version": "2.17.0"})
        return httpx.Response(404, json={"detail": "not found"})
    return httpx.MockTransport(handler)


ALERTS = [
    {"alert": "SQL Injection", "risk": "High", "url": "https://demo.local/item?id=1",
     "param": "id", "cweid": "89"},
    {"alert": "Reflected XSS", "risk": "Medium", "url": "https://demo.local/search?q=x",
     "param": "q"},
    {"alert": "X-Content-Type-Options missing", "risk": "Low",
     "url": "https://demo.local/", "param": ""},
    # duplicate of the SQLi — must collapse
    {"alert": "SQL Injection", "risk": "High", "url": "https://demo.local/item?id=1",
     "param": "id"},
    # off-scope host — the orchestrator must drop this
    {"alert": "SQL Injection", "risk": "High", "url": "https://evil.com/x?p=1",
     "param": "p"},
]


# --- client flow -------------------------------------------------------------

@pytest.mark.asyncio
async def test_scan_stops_zap_when_budget_elapses():
    """If a scan never reaches 100% within max_wait, ZAP is told to stop so it
    does not keep scanning after we return."""
    stopped: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p.endswith("/spider/action/scan/") or p.endswith("/ascan/action/scan/"):
            return httpx.Response(200, json={"scan": "0"})
        if p.endswith("/spider/view/status/") or p.endswith("/ascan/view/status/"):
            return httpx.Response(200, json={"status": "40"})  # never finishes
        if p.endswith("/spider/action/stop/") or p.endswith("/ascan/action/stop/"):
            stopped.append(p)
            return httpx.Response(200, json={"Result": "OK"})
        if p.endswith("/core/view/alerts/"):
            return httpx.Response(200, json={"alerts": []})
        return httpx.Response(200, json={})

    async with ZapClient("http://zap", "k",
                         transport=httpx.MockTransport(handler), poll_interval=0) as z:
        await z.scan("https://demo.local", max_wait=0.05)

    assert any("spider/action/stop" in s for s in stopped)
    assert any("ascan/action/stop" in s for s in stopped)


@pytest.mark.asyncio
async def test_scan_stops_zap_when_cancelled_midscan():
    """Quitting mid-scan (task cancelled) must still tell ZAP to stop."""
    import asyncio
    stopped: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p.endswith("/action/scan/"):
            return httpx.Response(200, json={"scan": "0"})
        if p.endswith("/view/status/"):
            return httpx.Response(200, json={"status": "40"})  # never done
        if p.endswith("/action/stop/"):
            stopped.append(p)
            return httpx.Response(200, json={"Result": "OK"})
        return httpx.Response(200, json={"alerts": []})

    z = ZapClient("http://zap", "k",
                  transport=httpx.MockTransport(handler), poll_interval=0.01)
    task = asyncio.create_task(z.scan("https://demo.local", max_wait=100))
    await asyncio.sleep(0.05)          # let the spider start and poll
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.05)          # let the shielded stop reach ZAP
    await z._client.aclose()
    assert any("/action/stop" in s for s in stopped), "scan was not stopped on cancel"


@pytest.mark.asyncio
async def test_scan_drives_spider_ascan_then_alerts():
    async with ZapClient("http://zap", "k", transport=_zap_transport(ALERTS),
                         poll_interval=0) as z:
        assert await z.version() == "2.17.0"
        alerts = await z.scan("https://demo.local", max_wait=5)
    assert len(alerts) == len(ALERTS)


# --- alert mapping -----------------------------------------------------------

def test_alerts_to_signals_high_first_and_dedupes():
    # default min_risk="Low" keeps Low, drops nothing here
    signals, score = alerts_to_signals(ALERTS, min_risk="Low")
    finding_lines = [s for s in signals if s.startswith("[ZAP")]
    # highest risk leads
    assert finding_lines[0].startswith("[ZAP High]")
    # the two identical SQLi alerts collapse to one
    assert sum("/item via 'id'" in s for s in signals) == 1
    # High(x2 distinct) + Medium + Low = 15+15+8+3
    assert score == 15 + 15 + 8 + 3


def test_risk_filter_drops_low_noise_and_counts_it():
    signals, score = alerts_to_signals(ALERTS, min_risk="Medium")
    # the Low header nit is gone from the listed findings...
    assert not any("X-Content-Type-Options" in s or "[ZAP Low]" in s for s in signals)
    # ...but it is accounted for, not silently dropped
    assert any("hidden" in s for s in signals)
    # only High + Medium contribute to the score now
    assert score == 15 + 15 + 8


def test_high_only_filter():
    signals, _ = alerts_to_signals(ALERTS, min_risk="High")
    listed = [s for s in signals if s.startswith("[ZAP")]
    assert listed and all(s.startswith("[ZAP High]") for s in listed)


# --- orchestrator integration ------------------------------------------------

@pytest.mark.asyncio
async def test_orchestrator_uses_zap_and_scope_gates_alerts(monkeypatch):
    settings = Settings(active_tests=True, use_zap=True,
                        zap_api_url="http://zap", zap_api_key="k",
                        enable_subdomain_enum=False, enable_sensitive_checks=False)
    scope = ScopeGuard(["*.demo.local", "demo.local"], [])
    orch = ReconOrchestrator(settings, scope)

    # patch ZapClient so _run_zap uses the mock transport and no sleeps
    import recon_orchestrator.zap_client as zc
    real_init = zc.ZapClient.__init__

    def patched_init(self, api_url, api_key, timeout=30.0, transport=None, poll_interval=3.0):
        real_init(self, api_url, api_key, timeout=timeout,
                  transport=_zap_transport(ALERTS), poll_interval=0)
    monkeypatch.setattr(zc.ZapClient, "__init__", patched_init)

    class P:
        async def probe(self, host): return HostProbe(host=host, status=200, port=443)
        async def send(self, r): raise AssertionError("built-in tester must not run")
        async def aclose(self): pass

    findings = await orch.run(["demo.local"], prober=P())
    all_signals = [s for f in findings for s in f.signals]
    assert any("SQL Injection" in s for s in all_signals)
    # the off-scope evil.com alert was filtered out
    assert not any("evil.com" in s for s in all_signals)
    # and no evil.com finding exists
    assert all("evil.com" not in f.host for f in findings)


@pytest.mark.asyncio
async def test_zap_sets_bypass_header_before_scanning(monkeypatch):
    """A protected preview needs a bypass header on every ZAP request; the
    orchestrator installs it as a Replacer rule before scanning."""
    seen: list[str] = []
    settings = Settings(active_tests=True, use_zap=True,
                        zap_api_url="http://zap", zap_api_key="k",
                        enable_subdomain_enum=False, enable_sensitive_checks=False,
                        extra_request_headers={"x-vercel-protection-bypass": "s3cret"})
    scope = ScopeGuard(["*.demo.local", "demo.local"], [])
    orch = ReconOrchestrator(settings, scope)

    import recon_orchestrator.zap_client as zc
    real_init = zc.ZapClient.__init__

    def patched_init(self, api_url, api_key, timeout=30.0, transport=None, poll_interval=3.0):
        real_init(self, api_url, api_key, timeout=timeout,
                  transport=_zap_transport(ALERTS, seen_headers=seen), poll_interval=0)
    monkeypatch.setattr(zc.ZapClient, "__init__", patched_init)

    class P:
        async def probe(self, host): return HostProbe(host=host, status=200, port=443)
        async def send(self, r): raise AssertionError("built-in tester must not run")
        async def aclose(self): pass

    await orch.run(["demo.local"], prober=P())
    assert "x-vercel-protection-bypass" in seen, "bypass header rule was not added to ZAP"


@pytest.mark.asyncio
async def test_use_zap_without_credentials_is_graceful(monkeypatch):
    settings = Settings(active_tests=True, use_zap=True,
                        enable_subdomain_enum=False, enable_sensitive_checks=False)
    scope = ScopeGuard(["demo.local"], [])
    orch = ReconOrchestrator(settings, scope)

    class P:
        async def probe(self, host): return HostProbe(host=host, status=200, port=443)
        async def send(self, r): raise AssertionError("should not send")
        async def aclose(self): pass

    # missing zap_api_key -> _run_zap returns [] without raising
    findings = await orch.run(["demo.local"], prober=P())
    assert findings == [] or all(f.signals for f in findings)
