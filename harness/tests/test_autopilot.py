"""Autopilot: draft confirmed active-test findings, never submit, armed only."""
from __future__ import annotations

import argparse
from types import SimpleNamespace

from harness import autopilot

# The exact shape the active engine writes: "<desc> at <path> via '<param>'".
REFLECTED = "reflected input (unencoded) — possible XSS at /search via 'q'"
SQLSIG = "database error provoked — possible SQL injection at /item via 'id'"
PASSIVE = "missing/weak security headers on mybox.test:80"


def _rec(signals):
    return SimpleNamespace(id="f1", host="mybox.test", url="https://mybox.test",
                           signals=signals)


def test_reflected_signal_becomes_honest_evidence():
    ev = autopilot.evidence_from_signal(_rec([REFLECTED]), REFLECTED)
    assert ev["vuln_type"] == "Reflected XSS"
    assert ev["affected_param"] == "q"
    payload = autopilot._payload_for("reflection")
    assert payload  # recon's real probe marker
    step = ev["steps_to_reproduce"][0]
    assert "https://mybox.test/search?q=" in step and payload in step
    assert payload in ev["observed_result"]        # the true detection
    assert "reflect" in ev["observed_result"].lower()


def test_sql_signal_becomes_honest_evidence():
    ev = autopilot.evidence_from_signal(_rec([SQLSIG]), SQLSIG)
    assert ev["vuln_type"].startswith("SQL Injection")
    assert ev["affected_param"] == "id"
    assert "/item?id=" in ev["steps_to_reproduce"][0]
    assert "database error" in ev["observed_result"].lower()


def test_passive_signal_is_not_drafted():
    # A passive lead (no active confirmation) must never become a draft.
    assert autopilot.evidence_from_signal(_rec([PASSIVE]), PASSIVE) is None


def test_drafts_for_collects_and_dedups():
    rec = _rec([REFLECTED, REFLECTED, SQLSIG, PASSIVE])
    drafts = autopilot.drafts_for(rec)
    assert [d["vuln_type"] for d in drafts] == ["Reflected XSS", "SQL Injection (error-based)"]


def test_autopilot_command_drafts_armed_only_and_never_submits(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path / "hunts"))
    # Keep the report prose pass offline and deterministic.
    monkeypatch.setattr("harness.humanizer.humanize", lambda t, **k: t)

    from harness import __main__ as cli
    from harness import findings_store as fs
    from harness.paths import ensure_dirs, programs_file
    from harness.programs import Program, Registry

    ensure_dirs()
    reg = Registry()
    reg.add(Program(name="mybox", in_scope=["*.mybox.test"], seeds=["mybox.test"],
                    mode="practice", active_tests=True))
    reg.add(Program(name="realp", in_scope=["*.r.test"], seeds=["r.test"],
                    mode="real"))
    reg.save(programs_file())

    lead = {"host": "mybox.test", "url": "https://mybox.test",
            "signals": [REFLECTED], "priority_score": 50}
    fs.save_finding(fs.record_from_lead("mybox", lead))
    # Same confirmed signal on a REAL program must be ignored by autopilot.
    fs.save_finding(fs.record_from_lead("realp", dict(lead, host="r.test",
                                                      url="https://r.test")))

    # The active pass is exercised elsewhere; here it is a no-op so the test is
    # hermetic. autopilot must never submit, so make submit explode if touched.
    monkeypatch.setattr(cli, "_cmd_auto", lambda args: None)
    monkeypatch.setattr(cli.engine, "submit_finding",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("autopilot must not submit")))

    cli._cmd_autopilot(argparse.Namespace(programs=None))

    armed = list(autopilot.playbook_dir("mybox").glob("*.md"))
    assert armed, "armed program should get a drafted report"
    assert "Reflected XSS" in armed[0].read_text()
    # real program: no drafts
    assert not list(autopilot.playbook_dir("realp").glob("*.md"))
