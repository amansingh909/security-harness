"""Tests for active payload testing (owned-assets-only mode).

The original branch shipped this crashing, bypassing the rate limiter, and
flagging every 200 as a finding. It also only injected into a guessed parameter
on the host root. These pin the corrected, discovery-driven behaviour: it finds
real inputs, scope-gates them, injects the payloads, and a signal means the
response actually showed something.
"""
from __future__ import annotations

import httpx
import pytest

from recon_orchestrator import payloads
from recon_orchestrator.active_discovery import extract_injection_points, inject
from recon_orchestrator.config import Settings
from recon_orchestrator.models import HostProbe
from recon_orchestrator.orchestrator import ReconOrchestrator
from recon_orchestrator.scope import ScopeGuard


# --- discovery ---------------------------------------------------------------

SAMPLE = """
<a href="/search?q=hi&lang=en">s</a>
<a href="https://demo.local/p?id=5">p</a>
<a href="https://evil.com/x?bad=1">off</a>
<form method="get" action="/find"><input name="term"></form>
<form method="post" action="/login"><input name="password"></form>
"""


def test_discovery_extracts_link_and_get_form_params():
    pts = extract_injection_points("https://demo.local/", SAMPLE)
    params = {(p.path, p.param) for p in pts}
    assert ("/search", "q") in params
    assert ("/search", "lang") in params
    assert ("/p", "id") in params
    assert ("/find", "term") in params          # GET form field


def test_discovery_skips_post_forms():
    pts = extract_injection_points("https://demo.local/", SAMPLE)
    assert all(p.param != "password" for p in pts), "POST form field must not be tested"


def test_discovery_dedupes_and_bounds():
    many = "".join(f'<a href="/?a{i}=x">l</a>' for i in range(100))
    pts = extract_injection_points("https://demo.local/", many, max_points=10)
    assert len(pts) == 10


def test_inject_preserves_sibling_params():
    pts = extract_injection_points("https://demo.local/", SAMPLE)
    q = next(p for p in pts if p.param == "q")
    url = inject(q, "PAYLOAD")
    assert "lang=en" in url and "q=PAYLOAD" in url


# --- honest detection --------------------------------------------------------

def test_reflection_uses_a_unique_marker():
    xss = next(t for t in payloads.TESTS if t.kind == "reflection")
    assert payloads.interpret(xss, f"x {xss.value} y") is not None
    assert payloads.interpret(xss, "<html><script>legit()</script></html>") is None


def test_sql_error_needs_a_db_error_not_just_200():
    sqli = next(t for t in payloads.TESTS if t.kind == "sql_error")
    assert payloads.interpret(sqli, "You have an error in your SQL syntax") is not None
    assert payloads.interpret(sqli, "<html>ok</html>") is None


def test_no_destructive_payloads():
    blob = " ".join(t.value.lower() for t in payloads.TESTS)
    assert "delete" not in blob


# --- pipeline integration ----------------------------------------------------

class ScriptedProber:
    """First request (the page fetch) returns HTML with a reflecting search
    endpoint; injected requests echo the query back (reflection) so the tester
    should flag XSS on /search via q."""

    def __init__(self):
        self.sent: list[httpx.Request] = []

    async def probe(self, host):
        return HostProbe(host=host, status=200, port=443)

    async def send(self, request):
        self.sent.append(request)
        if request.url.query:
            # reflect the decoded query verbatim -> the injected marker comes back
            from urllib.parse import unquote
            return httpx.Response(
                200, text="<html>" + unquote(request.url.query) + "</html>",
                request=request)
        # the page fetch: advertise a search endpoint with a query param
        return httpx.Response(
            200, request=request, text='<a href="/search?q=x">go</a>')

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_active_tests_off_by_default():
    settings = Settings(enable_subdomain_enum=False, enable_sensitive_checks=False)
    assert settings.active_tests is False
    orch = ReconOrchestrator(settings, ScopeGuard(["*.demo.local", "demo.local"], []))
    prober = ScriptedProber()
    await orch.run(["demo.local"], prober=prober)
    assert prober.sent == [], "active requests sent with active_tests off"


@pytest.mark.asyncio
async def test_active_tests_discover_then_inject_and_flag():
    settings = Settings(active_tests=True, enable_subdomain_enum=False,
                        enable_sensitive_checks=False)
    orch = ReconOrchestrator(settings, ScopeGuard(["*.demo.local", "demo.local"], []))
    prober = ScriptedProber()
    findings = await orch.run(["demo.local"], prober=prober)

    # it fetched the page, then injected into the discovered /search?q= param
    assert any(r.url.query for r in prober.sent), "never injected into a param"
    xss = [s for f in findings for s in f.signals
           if "XSS" in s and "/search" in s and "q" in s]
    assert xss, f"expected a reflected-XSS signal on /search, got {[f.signals for f in findings]}"


@pytest.mark.asyncio
async def test_active_tests_scope_gate_offsite_links():
    """A page linking off-domain must not get payloads sent off-domain."""
    class OffsiteProber(ScriptedProber):
        async def send(self, request):
            self.sent.append(request)
            if not request.url.query:
                return httpx.Response(
                    200, request=request,
                    text='<a href="https://evil.com/x?bad=1">off</a>')
            return httpx.Response(200, text="ok", request=request)

    settings = Settings(active_tests=True, enable_subdomain_enum=False,
                        enable_sensitive_checks=False)
    orch = ReconOrchestrator(settings, ScopeGuard(["*.demo.local", "demo.local"], []))
    prober = OffsiteProber()
    await orch.run(["demo.local"], prober=prober)

    hosts_hit = {r.url.host for r in prober.sent}
    assert "evil.com" not in hosts_hit, "payload sent to an out-of-scope host"
