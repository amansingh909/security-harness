from recon_orchestrator.models import Fingerprint, HostProbe
from recon_orchestrator.triage import score_host, triage


def test_admin_and_nonprod_rank_high():
    probe = HostProbe(host="admin.dev.example.com", status=200, port=443)
    finding = score_host(probe)
    assert finding.priority_score >= 7  # admin(4) + non-prod(3)
    assert any("admin" in s for s in finding.signals)
    assert any("non-prod" in s for s in finding.signals)


def test_auth_boundary_and_version_signals():
    probe = HostProbe(
        host="api.example.com", status=403, port=443,
        fingerprints=[Fingerprint(product="nginx", version="1.18.0", evidence="Server")],
    )
    finding = score_host(probe)
    assert any("403" in s for s in finding.signals)
    assert any("CVE surface" in s for s in finding.signals)


def test_boring_host_is_dropped_by_triage():
    boring = HostProbe(host="www.example.com", status=200, port=443)
    interesting = HostProbe(host="jenkins.example.com", status=200, port=443)
    ranked = triage([boring, interesting])
    assert [c.host for c in ranked] == ["jenkins.example.com"]


def test_errored_probes_excluded():
    ranked = triage([HostProbe(host="dead.example.com", error="unreachable")])
    assert ranked == []


def test_non_standard_port_flagged():
    finding = score_host(HostProbe(host="x.example.com", status=200, port=8080))
    assert any("non-standard port" in s for s in finding.signals)
