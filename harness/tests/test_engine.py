"""Engine tests that only need bounty-reporter (installed editable in the venv).
recon/classifier paths need network/torch and are exercised via the TUI smoke."""
import pytest

from harness import engine


def _write(path, mapping):
    import yaml
    path.write_text(yaml.safe_dump(mapping), encoding="utf-8")
    return str(path)


def test_render_report_refuses_unfilled_scaffold(tmp_path):
    from harness.findings import finding_template

    p = tmp_path / "finding.yaml"
    p.write_text(finding_template("acme", {"host": "x.acme.com"}), encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        engine.render_report(str(p))
    assert "TODO" in str(exc.value)


def test_render_report_produces_artifacts(tmp_path):
    pytest.importorskip("bounty_reporter")
    p = _write(tmp_path / "finding.yaml", {
        "program": "acme",
        "vuln_type": "IDOR",
        "asset": "https://app.acme.com/api/invoices/{id}",
        "cwe": "CWE-639",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "steps_to_reproduce": ["make two accounts", "swap the id", "read victim record"],
        "observed_result": "victim invoice returned",
        "impact": "any user reads any invoice",
    })
    result = engine.render_report(p)
    assert result["rating"] == "MEDIUM"
    assert result["cvss"] == 6.5
    out = tmp_path / "out"
    assert (out / f"{result['fingerprint']}.md").exists()
    assert (out / f"{result['fingerprint']}.hackerone.json").exists()
    assert (out / f"{result['fingerprint']}.bugcrowd.json").exists()


def test_available_reports_components():
    avail = engine.available()
    assert set(avail) == {"recon", "reporter", "classifier"}
    assert all(isinstance(v, bool) for v in avail.values())


def test_draft_report_humanizes_prose_but_leaves_evidence(monkeypatch):
    pytest.importorskip("bounty_reporter")
    import harness.humanizer as hz
    monkeypatch.setattr(hz, "humanize", lambda text, **k: f"HUMANIZED:{text}")

    finding = {
        "program": "acme",
        "vuln_type": "IDOR",
        "asset": "https://app.acme.com/api/invoices/{id}",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe": "CWE-639",
        "summary": "The invoice endpoint has no ownership check.",
        "steps_to_reproduce": ["make two accounts", "GET /api/invoices/4021"],
        "observed_result": "User B's invoice returned under User A's session.",
        "impact": "Any user can read any invoice by id.",
        "remediation": "Enforce an ownership check on the invoice id.",
    }
    md = engine.draft_report(finding)

    # prose fields are humanized
    assert "HUMANIZED:Any user can read any invoice by id." in md
    assert "HUMANIZED:The invoice endpoint has no ownership check." in md
    assert "HUMANIZED:Enforce an ownership check on the invoice id." in md
    # evidence is left byte-for-byte
    assert "GET /api/invoices/4021" in md
    assert "HUMANIZED:make two accounts" not in md           # steps not humanized
    assert "**Observed result:** User B's invoice returned under User A's session." in md
    assert "HUMANIZED:User B" not in md                       # observed_result not humanized


def test_draft_report_refuses_a_finding_without_evidence():
    pytest.importorskip("bounty_reporter")
    with pytest.raises(ValueError):
        engine.draft_report({"program": "p", "vuln_type": "X", "asset": "a"})
