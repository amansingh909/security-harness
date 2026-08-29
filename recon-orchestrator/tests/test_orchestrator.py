import pytest

from recon_orchestrator.config import Settings
from recon_orchestrator.models import Fingerprint, HostProbe
from recon_orchestrator.orchestrator import ReconOrchestrator
from recon_orchestrator.scope import ScopeGuard


class FakeProber:
    """Stub that returns canned probes so the pipeline runs with no network."""
    def __init__(self, responses):
        self._responses = responses
        self.probed = []

    async def probe(self, host):
        self.probed.append(host)
        return self._responses[host]

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_pipeline_gates_scope_and_triages():
    settings = Settings(requests_per_second=100, cve_index_url=None)
    scope = ScopeGuard(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    orch = ReconOrchestrator(settings, scope)

    responses = {
        "jenkins.example.com": HostProbe(
            host="jenkins.example.com", url="https://jenkins.example.com",
            status=403, port=443,
            fingerprints=[Fingerprint(product="nginx", version="1.18.0",
                                      evidence="Server: nginx/1.18.0")],
        ),
        "www.example.com": HostProbe(host="www.example.com", status=200, port=443),
    }
    prober = FakeProber(responses)

    seeds = [
        "jenkins.example.com",     # in scope, interesting
        "www.example.com",         # in scope, boring
        "admin.example.com",       # excluded -> must never be probed
        "evil.com",                # out of scope -> must never be probed
    ]
    findings = await orch.run(seeds, prober=prober)

    # scope gate: only the two authorized hosts were ever touched
    assert set(prober.probed) == {"jenkins.example.com", "www.example.com"}
    assert "admin.example.com" not in prober.probed
    assert "evil.com" not in prober.probed

    # triage: boring host dropped, interesting host surfaced with signals + note
    assert [f.host for f in findings] == ["jenkins.example.com"]
    top = findings[0]
    assert top.priority_score > 0
    assert any("403" in s for s in top.signals)
    assert "UNVERIFIED" in top.note


@pytest.mark.asyncio
async def test_no_authorized_seeds_returns_empty():
    settings = Settings()
    scope = ScopeGuard(in_scope=["example.com"])
    orch = ReconOrchestrator(settings, scope)
    findings = await orch.run(["evil.com", "other.net"], prober=FakeProber({}))
    assert findings == []
