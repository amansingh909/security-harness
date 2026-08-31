"""Tests for the recon enrichment stages wired into ReconOrchestrator.run.

subdomain_enum, sensitive_checks and tech_detect were built and tested in
isolation but never called from the run path — the pipeline only probed the
seeds you handed it. These tests pin them into the pipeline.
"""
from __future__ import annotations

import pytest

from recon_orchestrator import orchestrator as orch_mod
from recon_orchestrator.config import Settings
from recon_orchestrator.models import Fingerprint, HostProbe
from recon_orchestrator.orchestrator import ReconOrchestrator
from recon_orchestrator.scope import ScopeGuard


class FakeProber:
    def __init__(self, responses: dict[str, HostProbe]) -> None:
        self._responses = responses
        self.probed: list[str] = []

    async def probe(self, host: str) -> HostProbe:
        self.probed.append(host)
        return self._responses.get(host, HostProbe(host=host, status=200, port=443))

    async def aclose(self) -> None:
        pass


# --- apex derivation ---------------------------------------------------------

@pytest.mark.parametrize("host,apex", [
    ("www.example.com", "example.com"),
    ("api.staging.example.com", "example.com"),
    ("example.com", "example.com"),
    ("localhost", ""),
])
def test_apex_of(host, apex):
    assert ReconOrchestrator._apex_of(host) == apex


# --- subdomain discovery -----------------------------------------------------

@pytest.mark.asyncio
async def test_discovery_adds_only_in_scope_hosts(monkeypatch):
    """crt.sh returns a mix; only names the scope authorizes are kept."""
    async def fake_crtsh(apex):
        return {"api.example.com", "dev.example.com", "leaked.evil.com"}
    monkeypatch.setattr(orch_mod, "fetch_crtsh_for_apex", fake_crtsh, raising=False)
    monkeypatch.setattr("recon_orchestrator.subdomain_enum.fetch_crtsh_for_apex",
                        fake_crtsh, raising=False)

    scope = ScopeGuard(in_scope=["*.example.com"], out_of_scope=[])
    orch = ReconOrchestrator(Settings(), scope)
    new = await orch._discover_subdomains(["www.example.com"])

    assert set(new) == {"api.example.com", "dev.example.com"}
    assert "leaked.evil.com" not in new


@pytest.mark.asyncio
async def test_discovery_adds_nothing_without_wildcard_scope(monkeypatch):
    """A fixed host-list scope (like Box) authorizes no new subdomains."""
    async def fake_crtsh(apex):
        return {"secret.example.com", "api.example.com"}
    monkeypatch.setattr("recon_orchestrator.subdomain_enum.fetch_crtsh_for_apex",
                        fake_crtsh, raising=False)

    scope = ScopeGuard(in_scope=["www.example.com"], out_of_scope=[])
    orch = ReconOrchestrator(Settings(), scope)
    assert await orch._discover_subdomains(["www.example.com"]) == []


@pytest.mark.asyncio
async def test_run_probes_discovered_subdomains(monkeypatch):
    """Discovered, in-scope subdomains are probed, not just the seeds."""
    async def fake_crtsh(apex):
        return {"api.example.com"}
    monkeypatch.setattr("recon_orchestrator.subdomain_enum.fetch_crtsh_for_apex",
                        fake_crtsh, raising=False)

    settings = Settings(enable_sensitive_checks=False, enable_port_sweep=False)
    scope = ScopeGuard(in_scope=["*.example.com"], out_of_scope=[])
    orch = ReconOrchestrator(settings, scope)
    prober = FakeProber({
        "api.example.com": HostProbe(host="api.example.com", status=403, port=443),
    })
    await orch.run(["www.example.com"], prober=prober)

    assert "api.example.com" in prober.probed  # discovery fed the prober


# --- sensitive-path enrichment ----------------------------------------------

@pytest.mark.asyncio
async def test_sensitive_hit_creates_a_finding_for_a_clean_host(monkeypatch):
    """A host with no triage signal but an exposed secret must still surface."""
    async def fake_sensitive(host, settings, ports=None):
        return [HostProbe(host=host, url=f"https://{host}/.git/config",
                          status=200, port=443, title="/.git/config")]
    monkeypatch.setattr("recon_orchestrator.sensitive_checks.run_sensitive_checks",
                        fake_sensitive, raising=False)

    settings = Settings(enable_subdomain_enum=False, enable_port_sweep=False)
    scope = ScopeGuard(in_scope=["*.example.com"], out_of_scope=[])
    orch = ReconOrchestrator(settings, scope)
    # www is "boring" (200, no signal) — triage alone would drop it.
    prober = FakeProber({"www.example.com": HostProbe(host="www.example.com",
                                                      status=200, port=443)})
    findings = await orch.run(["www.example.com"], prober=prober)

    assert [f.host for f in findings] == ["www.example.com"]
    assert any(".git" in s for s in findings[0].signals)
    assert findings[0].priority_score >= 6  # secret exposure scores high


@pytest.mark.asyncio
async def test_sensitive_hit_bumps_an_existing_finding(monkeypatch):
    async def fake_sensitive(host, settings, ports=None):
        return [HostProbe(host=host, url=f"https://{host}/.env",
                          status=200, port=443, title="/.env")]
    monkeypatch.setattr("recon_orchestrator.sensitive_checks.run_sensitive_checks",
                        fake_sensitive, raising=False)

    settings = Settings(enable_subdomain_enum=False, enable_port_sweep=False)
    scope = ScopeGuard(in_scope=["*.example.com"], out_of_scope=[])
    orch = ReconOrchestrator(settings, scope)
    # already-interesting host: 403 boundary
    prober = FakeProber({"jenkins.example.com": HostProbe(
        host="jenkins.example.com", status=403, port=443)})
    findings = await orch.run(["jenkins.example.com"], prober=prober)

    top = findings[0]
    assert any(".env" in s for s in top.signals)
    assert any("403" in s for s in top.signals)  # kept its original signal
    assert top.priority_score >= 6 + 2           # secret + boundary


@pytest.mark.asyncio
async def test_stages_off_by_flag_make_no_calls(monkeypatch):
    called = {"crtsh": False, "sensitive": False}

    async def fake_crtsh(apex):
        called["crtsh"] = True
        return set()

    async def fake_sensitive(host, settings, ports=None):
        called["sensitive"] = True
        return []

    monkeypatch.setattr("recon_orchestrator.subdomain_enum.fetch_crtsh_for_apex",
                        fake_crtsh, raising=False)
    monkeypatch.setattr("recon_orchestrator.sensitive_checks.run_sensitive_checks",
                        fake_sensitive, raising=False)

    settings = Settings(enable_subdomain_enum=False, enable_sensitive_checks=False,
                        enable_port_sweep=False)
    scope = ScopeGuard(in_scope=["*.example.com"], out_of_scope=[])
    orch = ReconOrchestrator(settings, scope)
    await orch.run(["www.example.com"], prober=FakeProber({}))

    assert called == {"crtsh": False, "sensitive": False}


@pytest.mark.asyncio
async def test_run_cancels_inflight_probes_when_cancelled():
    """Quitting mid-scan cancels run(); its in-flight probes must be cancelled
    too (a probe driving ZAP stops the ZAP scan on cancel)."""
    import asyncio
    from recon_orchestrator.config import Settings
    cancelled = {"probe": False}

    class SlowProber:
        async def probe(self, host):
            try:
                await asyncio.sleep(100)
            except asyncio.CancelledError:
                cancelled["probe"] = True
                raise
            return HostProbe(host=host, status=200, port=443)

        async def aclose(self):
            pass

    orch = ReconOrchestrator(
        Settings(enable_subdomain_enum=False, enable_sensitive_checks=False),
        ScopeGuard(in_scope=["demo.local"], out_of_scope=[]),
    )
    task = asyncio.create_task(orch.run(["demo.local"], prober=SlowProber()))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.05)
    assert cancelled["probe"], "in-flight probe was not cancelled with run()"
