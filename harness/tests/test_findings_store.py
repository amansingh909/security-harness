"""Per-finding record store: one file per finding, verdicts survive re-scans."""
from __future__ import annotations

from harness import findings_store as fs

VULN = {
    "host": "dev.example.com",
    "service": {
        "host": "dev.example.com", "port": 443, "scheme": "https",
        "server": "nginx/1.18.0", "powered_by": "", "status_code": 200,
    },
    "cves": [
        {"id": "CVE-2021-23017", "product": "nginx", "version": "1.18.0",
         "cvss_severity": "HIGH", "cvss_score": 7.7,
         "why": "resolver off-by-one", "source": "cve-index"},
    ],
    "priority_score": 42,
}


def test_record_from_vuln_maps_scan_shape():
    rec = fs.record_from_vuln("acme", VULN)
    assert rec.program == "acme"
    assert rec.host == "dev.example.com"
    assert rec.service["port"] == 443
    assert rec.cves[0]["id"] == "CVE-2021-23017"
    assert rec.priority_score == 42
    assert rec.status == "needs_check"  # machine-assigned until a human rules


def test_finding_id_is_stable_per_host_port():
    a = fs.record_from_vuln("acme", VULN)
    b = fs.record_from_vuln("acme", VULN)
    assert a.id == b.id  # same host:port -> same id, so re-scans update in place
    other = dict(VULN, service=dict(VULN["service"], port=8443))
    assert fs.record_from_vuln("acme", other).id != a.id


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    rec = fs.record_from_vuln("acme", VULN)
    fs.save_finding(rec)
    loaded = fs.load_findings("acme")
    assert [r.id for r in loaded] == [rec.id]
    assert loaded[0].cves[0]["id"] == "CVE-2021-23017"


def test_update_status_persists(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    rec = fs.record_from_vuln("acme", VULN)
    fs.save_finding(rec)
    fs.update_status("acme", rec.id, "real", note="confirmed by hand")
    got = fs.get_finding("acme", rec.id)
    assert got.status == "real"
    assert got.note == "confirmed by hand"


def test_upsert_preserves_operator_verdict_but_refreshes_machine_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    rec = fs.record_from_vuln("acme", VULN)
    fs.save_finding(rec)
    fs.update_status("acme", rec.id, "real")

    # A later scan re-finds the same host, now with an extra CVE.
    extra = VULN["cves"] + [
        {"id": "CVE-2022-0001", "product": "nginx", "version": "1.18.0",
         "cvss_severity": "MEDIUM", "cvss_score": 5.0, "why": "x",
         "source": "cve-index"},
    ]
    fresh = fs.record_from_vuln("acme", dict(VULN, cves=extra))
    fs.upsert_findings("acme", [fresh])

    got = fs.get_finding("acme", rec.id)
    assert got.status == "real"      # operator verdict preserved across the re-scan
    assert len(got.cves) == 2        # machine-derived fields refreshed


def test_upsert_new_finding_is_needs_check(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    fresh = fs.record_from_vuln("acme", VULN)
    n = fs.upsert_findings("acme", [fresh])
    assert n == 1
    assert fs.get_finding("acme", fresh.id).status == "needs_check"


# A recon lead: this is where the real findings live (signals like XSS,
# exposed paths, version disclosure), not in the CVE-correlation pass.
LEAD = {
    "host": "testasp.vulnweb.com",
    "url": "http://testasp.vulnweb.com",
    "priority_score": 7,
    "signals": [
        "version disclosed (microsoft-iis 8.5) — CVE surface",
        "reflected input (unencoded) — possible XSS at /Search.asp via 'tfSearch'",
    ],
    "fingerprints": [
        {"product": "microsoft-iis", "version": "8.5",
         "evidence": "server: Microsoft-IIS/8.5"},
    ],
    "cve_candidates": [],
    "status": 200,
}


def test_record_from_lead_carries_signals_and_fingerprints():
    rec = fs.record_from_lead("acme", LEAD)
    assert rec.host == "testasp.vulnweb.com"
    assert rec.url == "http://testasp.vulnweb.com"
    assert any("XSS" in s for s in rec.signals)
    assert rec.fingerprints[0]["product"] == "microsoft-iis"
    assert rec.priority_score == 7
    assert rec.status == "needs_check"


def test_record_from_lead_id_is_stable_per_host(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    a = fs.record_from_lead("acme", LEAD)
    b = fs.record_from_lead("acme", LEAD)
    assert a.id == b.id  # a re-run updates the same host in place


def test_record_outcome_persists_verdict_and_bounty(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    rec = fs.record_from_lead("clear", LEAD)
    fs.save_finding(rec)
    fs.record_outcome("clear", rec.id, "paid", bounty=750.0)
    got = fs.get_finding("clear", rec.id)
    assert got.outcome == "paid"
    assert got.bounty == 750.0


def test_set_evidence_persists_and_survives_a_rescan(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    rec = fs.record_from_lead("acme", LEAD)
    fs.save_finding(rec)
    fs.set_evidence("acme", rec.id, {"vuln_type": "XSS", "impact": "session theft"})
    assert fs.get_finding("acme", rec.id).evidence["vuln_type"] == "XSS"

    # a later scan re-files the same host; the operator's evidence is kept
    fs.upsert_findings("acme", [fs.record_from_lead("acme", LEAD)])
    got = fs.get_finding("acme", rec.id)
    assert got.evidence.get("vuln_type") == "XSS"
