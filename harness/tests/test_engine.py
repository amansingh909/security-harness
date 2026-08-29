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
