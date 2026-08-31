"""Tests for active payload testing (owned-assets-only mode).

The original branch shipped this crashing (`httpx.utils.quote` does not exist),
bypassing the rate limiter, and flagging every 200 as a finding. These pin the
corrected behaviour: it runs, it is rate-limited, and a signal means the
response actually showed something.
"""
from __future__ import annotations

import httpx
import pytest

from recon_orchestrator import payloads
from recon_orchestrator.config import Settings
from recon_orchestrator.orchestrator import ReconOrchestrator
from recon_orchestrator.ratelimit import TokenBucket
from recon_orchestrator.scope import ScopeGuard


# --- request building --------------------------------------------------------

def test_build_requests_does_not_crash_and_encodes():
    """`httpx.utils.quote` did not exist; building any request raised."""
    reqs = payloads.build_requests("https://demo.local")
    assert reqs, "no requests built"
    for _test, req in reqs:
        assert isinstance(req, httpx.Request)
        assert req.method == "GET"
        assert str(req.url).startswith("https://demo.local")


def test_no_destructive_payloads():
    """The original had a POST {'action':'delete'} vector; it must be gone."""
    for _test, req in payloads.build_requests("https://demo.local"):
        assert req.method == "GET"
    blob = " ".join(t.value.lower() for t in payloads.TESTS)
    assert "delete" not in blob


# --- honest detection --------------------------------------------------------

def test_reflection_uses_a_unique_marker():
    xss = next(t for t in payloads.TESTS if t.kind == "reflection")
    # our marker reflected -> signal
    assert payloads.interpret(xss, f"prefix {xss.value} suffix") is not None
    # a page's OWN <script> is not our input -> no false positive
    assert payloads.interpret(xss, "<html><script>legit()</script></html>") is None


def test_sql_error_needs_a_db_error_not_just_200():
    sqli = next(t for t in payloads.TESTS if t.kind == "sql_error")
    assert payloads.interpret(sqli, "You have an error in your SQL syntax") is not None
    assert payloads.interpret(sqli, "<html>ok</html>") is None


# --- pipeline integration ----------------------------------------------------

class RecordingProber:
    """Prober stub that records every request sent through the rate-limited
    path and returns a body the tester should flag."""

    def __init__(self):
        self.sent: list[httpx.Request] = []
        self._client = None

    async def probe(self, host):
        from recon_orchestrator.models import HostProbe
        return HostProbe(host=host, status=200, port=443)

    async def send(self, request):
        self.sent.append(request)
        resp = httpx.Response(200, text="You have an error in your SQL syntax near '''",
                              request=request)
        return resp

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_active_tests_off_by_default():
    settings = Settings(enable_subdomain_enum=False, enable_sensitive_checks=False)
    assert settings.active_tests is False
    scope = ScopeGuard(in_scope=["*.demo.local", "demo.local"], out_of_scope=[])
    orch = ReconOrchestrator(settings, scope)
    prober = RecordingProber()
    await orch.run(["demo.local"], prober=prober)
    assert prober.sent == [], "active requests were sent with active_tests off"


@pytest.mark.asyncio
async def test_active_tests_run_and_surface_a_signal_when_enabled():
    settings = Settings(active_tests=True, enable_subdomain_enum=False,
                        enable_sensitive_checks=False)
    scope = ScopeGuard(in_scope=["*.demo.local", "demo.local"], out_of_scope=[])
    orch = ReconOrchestrator(settings, scope)
    prober = RecordingProber()
    findings = await orch.run(["demo.local"], prober=prober)

    assert prober.sent, "active_tests enabled but no requests sent"
    # the SQL-error body should have produced a finding with an sqli signal
    sqli_signals = [s for f in findings for s in f.signals if "SQL injection" in s]
    assert sqli_signals, f"expected an SQL-injection signal, got {[f.signals for f in findings]}"
