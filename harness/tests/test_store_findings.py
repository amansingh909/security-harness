import yaml

from harness import store
from harness.findings import finding_template, unfilled_todos


def test_store_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    leads = [{"host": "dev.acme.com", "priority_score": 7, "signals": ["non-prod"]}]
    path = store.save_leads("acme", leads)
    assert path.exists()
    assert store.load_leads("acme") == leads
    assert store.last_run("acme") is not None


def test_store_empty_when_never_run(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    assert store.load_leads("never") == []
    assert store.last_run("never") is None


def test_finding_template_prefills_facts_and_todos():
    lead = {
        "host": "dev-api.acme.com",
        "url": "https://dev-api.acme.com",
        "priority_score": 8,
        "signals": ["non-prod naming ('dev')", "version disclosed (nginx 1.18.0)"],
        "cve_candidates": [
            {"cve_id": "CVE-2021-23017", "product": "nginx", "version": "1.18.0",
             "cvss_severity": "HIGH"}
        ],
        "fingerprints": [{"product": "nginx", "version": "1.18.0"}],
    }
    text = finding_template("acme", lead)
    body = yaml.safe_load(text)  # header lines are comments, so this parses cleanly

    # known facts are filled in from recon
    assert body["program"] == "acme"
    assert body["asset"] == "https://dev-api.acme.com"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2021-23017" in body["references"]
    assert body["_recon_context"]["fingerprints"] == ["nginx 1.18.0"]

    # evidence the human must supply is left as explicit TODOs, never invented
    assert body["vuln_type"].startswith("TODO")
    assert body["impact"].startswith("TODO")
    assert all(step.startswith("TODO") for step in body["steps_to_reproduce"])


def test_unfilled_todos_flags_placeholders():
    scaffold = yaml.safe_load(finding_template("acme", {"host": "x.acme.com"}))
    todos = unfilled_todos(scaffold)
    # a fresh scaffold has every required field unfilled except the pre-filled asset
    assert "vuln_type" in todos
    assert "impact" in todos
    assert "observed_result" in todos
    assert "steps_to_reproduce" in todos
    assert "asset" not in todos  # pre-filled from recon


def test_unfilled_todos_empty_when_filled():
    data = {
        "vuln_type": "IDOR",
        "asset": "https://x.acme.com/a",
        "observed_result": "got another user's record",
        "impact": "reads any user's data",
        "steps_to_reproduce": ["log in as A", "request B's id", "observe leak"],
    }
    assert unfilled_todos(data) == []
