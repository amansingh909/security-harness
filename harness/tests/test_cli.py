"""Regression tests for the `harness` CLI entrypoint.

Every test here pins a bug that actually shipped. `__main__.py` had no coverage,
which is how a `store.Registry` that does not exist and a relative import that
escapes the package both survived into a release.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import types

from harness import __main__ as cli


# --- ~/.harness/.env loading -------------------------------------------------

def test_load_env_file_reads_keys(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        "H1_API_KEY=tok\n"
        "# a comment\n"
        "\n"
        "H1_IDENTIFIER=me\n"
        "MALFORMED_NO_EQUALS\n"
    )
    monkeypatch.setattr(cli, "config_dir", lambda: tmp_path)
    monkeypatch.delenv("H1_API_KEY", raising=False)
    monkeypatch.delenv("H1_IDENTIFIER", raising=False)

    cli._load_env_file()

    assert os.environ["H1_API_KEY"] == "tok"
    assert os.environ["H1_IDENTIFIER"] == "me"


def test_load_env_file_does_not_override_real_env(tmp_path, monkeypatch):
    """An explicit `H1_API_KEY=... harness global` must win over the file."""
    (tmp_path / ".env").write_text("H1_API_KEY=from-file\n")
    monkeypatch.setattr(cli, "config_dir", lambda: tmp_path)
    monkeypatch.setenv("H1_API_KEY", "from-env")

    cli._load_env_file()

    assert os.environ["H1_API_KEY"] == "from-env"


def test_load_env_file_tolerates_missing_file(tmp_path, monkeypatch):
    """No .env is the normal case for a fresh install; it must not raise."""
    monkeypatch.setattr(cli, "config_dir", lambda: tmp_path / "does-not-exist")
    cli._load_env_file()  # must not raise


def test_load_env_file_strips_whitespace(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("  H1_IDENTIFIER = spaced  \n")
    monkeypatch.setattr(cli, "config_dir", lambda: tmp_path)
    monkeypatch.delenv("H1_IDENTIFIER", raising=False)

    cli._load_env_file()

    assert os.environ["H1_IDENTIFIER"] == "spaced"


# --- repo path resolution ----------------------------------------------------

def test_cve_index_dir_honours_override(monkeypatch):
    monkeypatch.setenv("HARNESS_REPO", os.sep + "somewhere")
    assert cli._cve_index_dir() == os.path.join(os.sep + "somewhere", "cve-index")


def test_cve_index_dir_derives_from_package_location(monkeypatch):
    """Was hardcoded to ~/security-harness/cve-index in three places."""
    monkeypatch.delenv("HARNESS_REPO", raising=False)
    assert cli._cve_index_dir().endswith("cve-index")


# --- names the CLI reaches for ----------------------------------------------

def test_names_used_by_cmd_global_exist():
    """`store.Registry.load(store.programs_file())` raised AttributeError:
    neither name lives on the store module."""
    from harness import engine, store
    from harness.paths import hunts_dir, programs_file  # noqa: F401
    from harness.programs import Registry  # noqa: F401

    for name in ("save_leads", "save_vulns", "load_vulns"):
        assert hasattr(store, name), f"store.{name} is missing"
    for name in ("run_recon", "scan_for_vulns", "render_batch_report",
                 "cve_index_health"):
        assert hasattr(engine, name), f"engine.{name} is missing"


def test_every_subcommand_handler_exists():
    """Each subparser sets func=<handler>; a missing one is a NameError at
    import time, but a renamed one only fails when that command is run."""
    for handler in ("_cmd_tui", "_cmd_list", "_cmd_add", "_cmd_add_prog",
                    "_cmd_hunt", "_cmd_scan", "_cmd_global", "_cmd_up",
                    "_cmd_down", "_cmd_auto", "_cmd_seed_practice",
                    "_cmd_set_header", "_cmd_show_policy",
                    "_cmd_outcome", "_cmd_lessons"):
        assert callable(getattr(cli, handler, None)), f"{handler} missing"


# --- service teardown: "own what you start, stop it when you're done" --------
#
# The leak these pin: harness `global`/`up` and the zap-daemon script started
# background services (Elasticsearch, cve-index, ZAP) that nothing ever stopped,
# so they idled for days after the run that spawned them had exited.

def _patch_teardown_primitives(monkeypatch) -> list[str]:
    """Replace the three stop primitives with recorders; return the call log."""
    calls: list[str] = []
    monkeypatch.setattr(cli, "_stop_cve_index", lambda: calls.append("cve"))
    monkeypatch.setattr(cli, "_compose_down", lambda: calls.append("compose"))
    monkeypatch.setattr(cli, "_stop_zap", lambda: calls.append("zap"))
    return calls


def test_cmd_down_stops_everything(monkeypatch):
    """`harness down` is the hard stop: cve-index + Elasticsearch + ZAP."""
    calls = _patch_teardown_primitives(monkeypatch)
    cli._cmd_down(argparse.Namespace())
    assert calls == ["cve", "compose", "zap"]


def test_teardown_only_if_owned_skips_unowned_stack(monkeypatch):
    """Auto-cleanup must not touch a stack this process didn't start."""
    calls = _patch_teardown_primitives(monkeypatch)
    monkeypatch.setattr(cli, "_we_started_cve_stack", False)
    cli._teardown_services(stop_zap=False, only_if_owned=True)
    assert calls == []


def test_teardown_only_if_owned_stops_owned_stack(monkeypatch):
    """Auto-cleanup stops the stack this process started, leaving ZAP alone."""
    calls = _patch_teardown_primitives(monkeypatch)
    monkeypatch.setattr(cli, "_we_started_cve_stack", True)
    cli._teardown_services(stop_zap=False, only_if_owned=True)
    assert calls == ["cve", "compose"]


def test_teardown_force_stops_everything_regardless_of_ownership(monkeypatch):
    calls = _patch_teardown_primitives(monkeypatch)
    monkeypatch.setattr(cli, "_we_started_cve_stack", False)
    cli._teardown_services(stop_zap=True, only_if_owned=False)
    assert calls == ["cve", "compose", "zap"]


def test_ensure_cve_index_adopts_healthy_without_ownership(monkeypatch):
    """A stack that's already healthy is adopted, not re-started or owned."""
    monkeypatch.setattr(cli, "_we_started_cve_stack", False)

    async def healthy(url="http://localhost:8080"):
        return True
    monkeypatch.setattr(cli, "_cve_index_healthy", healthy)

    def no_popen(*a, **k):
        raise AssertionError("must not start a server when one is healthy")
    monkeypatch.setattr(cli.subprocess, "Popen", no_popen)

    asyncio.run(cli._ensure_cve_index_running())
    assert cli._we_started_cve_stack is False


def test_ensure_cve_index_claims_ownership_when_it_starts_one(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))  # keep the pid file out of real $HOME
    monkeypatch.setattr(cli, "_we_started_cve_stack", False)

    state = {"n": 0}

    async def health(url="http://localhost:8080"):
        state["n"] += 1
        return state["n"] > 1  # unhealthy at entry, healthy once we've "started" it
    monkeypatch.setattr(cli, "_cve_index_healthy", health)
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: None)

    class FakeProc:
        pid = 4321

        def poll(self):
            return None
    monkeypatch.setattr(cli.subprocess, "Popen", lambda *a, **k: FakeProc())

    asyncio.run(cli._ensure_cve_index_running())
    assert cli._we_started_cve_stack is True


def test_stop_zap_is_noop_when_zap_is_down(monkeypatch):
    monkeypatch.setattr(cli, "_zap_is_up", lambda: False)
    # No httpx call and no subprocess should happen; simply must not raise.
    cli._stop_zap()


def test_stop_zap_uses_the_shutdown_api(monkeypatch):
    monkeypatch.setattr(cli, "_zap_is_up", lambda: True)
    monkeypatch.setattr(cli, "_zap_endpoint", lambda: ("http://z:8081", "secret"))
    seen: dict = {}

    def fake_get(url, params=None, timeout=None):
        seen["url"] = url
        seen["params"] = params
        return object()
    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(get=fake_get))

    cli._stop_zap()
    assert seen["url"] == "http://z:8081/JSON/core/action/shutdown/"
    assert seen["params"] == {"apikey": "secret"}


def test_offer_teardown_stops_services_on_default_yes(monkeypatch):
    monkeypatch.setattr(cli, "_zap_is_up", lambda: True)

    async def healthy(url="http://localhost:8080"):
        return True
    monkeypatch.setattr(cli, "_cve_index_healthy", healthy)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")  # bare Enter = yes

    got: dict = {}
    monkeypatch.setattr(cli, "_teardown_services",
                        lambda **kw: got.update(kw))
    cli._offer_service_teardown()
    assert got == {"stop_zap": True, "only_if_owned": False}


def test_offer_teardown_is_silent_when_nothing_runs(monkeypatch):
    monkeypatch.setattr(cli, "_zap_is_up", lambda: False)

    async def down(url="http://localhost:8080"):
        return False
    monkeypatch.setattr(cli, "_cve_index_healthy", down)

    def no_input(*a, **k):
        raise AssertionError("must not prompt when nothing is running")
    monkeypatch.setattr("builtins.input", no_input)

    def no_teardown(**kw):
        raise AssertionError("must not tear down when nothing is running")
    monkeypatch.setattr(cli, "_teardown_services", no_teardown)

    cli._offer_service_teardown()  # must return quietly


def test_zap_daemon_script_supports_stop_and_status():
    """The zap-daemon helper must expose a clean shutdown path, not just start."""
    path = os.path.expanduser("~/.local/bin/zap-daemon")
    if not os.path.exists(path):
        return  # environment without the helper installed
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    assert "stop)" in text and "status)" in text
    assert "core/action/shutdown" in text


# --- startup: launch cve-index without poetry ---------------------------------
#
# The crash this pins: `_ensure_cve_index_running` started the server with
# `poetry run cve-index serve`, but there is no poetry env — poetry then spins
# up an empty virtualenv missing every cve-index dependency, the server exits
# instantly, and the whole `global`/`auto` run aborts at step 0. Start it with
# the interpreter already running the harness, as `python -m cve_index serve`.

def test_ensure_cve_index_starts_server_without_poetry(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))  # keep the pid file out of real $HOME
    monkeypatch.setattr(cli, "_we_started_cve_stack", False)

    state = {"n": 0}

    async def health(url="http://localhost:8080"):
        state["n"] += 1
        return state["n"] > 1  # unhealthy at entry, healthy once "started"
    monkeypatch.setattr(cli, "_cve_index_healthy", health)
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: None)

    captured: dict = {}

    class FakeProc:
        pid = 4321

        def poll(self):
            return None

    def fake_popen(argv, *a, **k):
        captured["argv"] = list(argv)
        return FakeProc()
    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    asyncio.run(cli._ensure_cve_index_running())

    assert "poetry" not in captured["argv"], "must not shell out to poetry"
    assert captured["argv"][0] == sys.executable
    assert captured["argv"][1:3] == ["-m", "cve_index"]
    assert "serve" in captured["argv"]


# --- startup: ingest the CVE corpus once if it's empty ------------------------
#
# global/auto never populated Elasticsearch, so every vuln lookup returned
# nothing and every report came back empty. The runner must ingest on a cold
# index (vectors == 0) and skip when data is already present.

def test_cve_corpus_is_populated_reads_vector_count():
    assert cli._cve_corpus_is_populated({"up": True, "vectors": 1200}) is True
    assert cli._cve_corpus_is_populated({"up": True, "vectors": 0}) is False
    assert cli._cve_corpus_is_populated({"up": False, "vectors": None}) is False


def test_ensure_cve_corpus_skips_ingest_when_populated(monkeypatch):
    async def health(url):
        return {"up": True, "vectors": 5000}
    monkeypatch.setattr(cli.engine, "cve_index_health", health)

    def no_run(*a, **k):
        raise AssertionError("must not ingest when the index already has data")
    monkeypatch.setattr(cli.subprocess, "run", no_run)

    asyncio.run(cli._ensure_cve_corpus())


def test_ensure_cve_corpus_ingests_full_when_empty(monkeypatch):
    async def health(url):
        return {"up": True, "vectors": 0}
    monkeypatch.setattr(cli.engine, "cve_index_health", health)

    captured: dict = {}

    class OK:
        returncode = 0

    def fake_run(argv, *a, **k):
        captured["argv"] = list(argv)
        return OK()
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    asyncio.run(cli._ensure_cve_corpus())

    assert captured["argv"][0] == sys.executable
    assert captured["argv"][1:3] == ["-m", "cve_index"]
    assert "ingest" in captured["argv"]
    assert "--mode" in captured["argv"] and "full" in captured["argv"]


# --- headless run: `harness auto` fills the review queue, no prompts ----------
#
# The autonomous entry point: recon + scan for every program, convert the scan
# output into per-finding records for the TUI to review. It must be fully
# non-interactive (cron/Hermes runs it) and must never upload.

def test_cmd_auto_fills_review_queue_without_prompts(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))

    from harness.programs import Program, Registry
    reg = Registry()
    reg.add(Program(name="acme", in_scope=["*.acme.com"], seeds=["www.acme.com"]))
    reg.save(tmp_path / "programs.yaml")

    async def _ok(*a, **k):
        return None
    monkeypatch.setattr(cli, "_ensure_cve_index_running", _ok)
    monkeypatch.setattr(cli, "_ensure_cve_corpus", _ok)

    async def fake_pipeline(registry, names):
        for name in names:
            cli.store.save_leads(name, [{
                "host": "dev.acme.com",
                "url": "http://dev.acme.com",
                "signals": ["sensitive path exposed (/info.php) — information disclosure"],
                "fingerprints": [{"product": "nginx", "version": "1.0"}],
                "cve_candidates": [],
                "priority_score": 10,
                "status": 200,
            }])
    monkeypatch.setattr(cli, "_run_pipeline", fake_pipeline)
    monkeypatch.setattr(cli, "_teardown_services", lambda **k: None)

    def no_input(*a, **k):
        raise AssertionError("`harness auto` must never prompt")
    monkeypatch.setattr("builtins.input", no_input)

    cli._cmd_auto(argparse.Namespace())

    from harness import findings_store as fs
    recs = fs.load_findings("acme")
    assert [r.host for r in recs] == ["dev.acme.com"]
    assert recs[0].status == "needs_check"
    assert any("/info.php" in s for s in recs[0].signals)


# --- practice vs real: the bright line, enforced ------------------------------
#
# In an autonomous run a REAL program is always passive (GET/HEAD) — it never
# sends attack traffic, whatever its stored active_tests flag says. Only a
# practice program (an intentionally-vulnerable target) arms the active engine.

def test_arm_for_mode_forces_real_passive_and_arms_practice():
    from harness.programs import Program
    real = Program(name="r", in_scope=["*.r.com"], seeds=["r.com"],
                   active_tests=True, mode="real")
    practice = Program(name="p", in_scope=["localhost"], seeds=["localhost"],
                       mode="practice")
    cli._arm_for_mode(real)
    cli._arm_for_mode(practice)
    assert real.active_tests is False   # real never active in auto — the bright line
    assert practice.active_tests is True


def test_auto_arms_programs_by_mode_before_the_pipeline(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    from harness.programs import Program, Registry
    reg = Registry()
    reg.add(Program(name="realp", in_scope=["*.r.com"], seeds=["r.com"],
                    active_tests=True, mode="real"))
    reg.add(Program(name="pract", in_scope=["localhost"], seeds=["localhost"],
                    mode="practice"))
    reg.save(tmp_path / "programs.yaml")

    async def _ok(*a, **k):
        return None
    monkeypatch.setattr(cli, "_ensure_cve_index_running", _ok)
    monkeypatch.setattr(cli, "_ensure_cve_corpus", _ok)
    monkeypatch.setattr(cli, "_teardown_services", lambda **k: None)

    seen: dict = {}

    async def capture_pipeline(registry, names):
        for name in names:
            seen[name] = registry.get(name).active_tests
    monkeypatch.setattr(cli, "_run_pipeline", capture_pipeline)

    cli._cmd_auto(argparse.Namespace())

    assert seen["realp"] is False   # real forced passive before any recon
    assert seen["pract"] is True    # practice armed


def test_auto_runs_only_the_requested_programs(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    from harness.programs import Program, Registry
    reg = Registry()
    reg.add(Program(name="a", in_scope=["*.a.com"], seeds=["a.com"]))
    reg.add(Program(name="b", in_scope=["*.b.com"], seeds=["b.com"]))
    reg.save(tmp_path / "programs.yaml")

    async def _ok(*a, **k):
        return None
    monkeypatch.setattr(cli, "_ensure_cve_index_running", _ok)
    monkeypatch.setattr(cli, "_ensure_cve_corpus", _ok)
    monkeypatch.setattr(cli, "_teardown_services", lambda **k: None)

    ran: list[str] = []

    async def capture(registry, names):
        ran.extend(names)
    monkeypatch.setattr(cli, "_run_pipeline", capture)

    cli._cmd_auto(argparse.Namespace(programs="a"))
    assert ran == ["a"]  # only the requested program, not b


# --- auto-refresh HackerOne scope so a run never uses stale scope -------------

def test_refresh_h1_scopes_updates_imported_program_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))  # never touch the real config
    monkeypatch.setenv("H1_IDENTIFIER", "id")
    monkeypatch.setenv("H1_API_KEY", "key")
    from harness.programs import Program, Registry
    reg = Registry()
    reg.add(Program(name="acme", in_scope=["old.acme.com"], seeds=["old.acme.com"],
                    h1_handle="acme"))
    reg.add(Program(name="manual", in_scope=["m.com"], seeds=["m.com"]))  # no handle

    import recon_orchestrator.hackerone_scope as h1

    async def fake_fetch(handle, identifier, token, **k):
        assert (handle, identifier, token) == ("acme", "id", "key")
        return (["*.acme.com", "api.acme.com"], ["admin.acme.com"])
    monkeypatch.setattr(h1, "fetch_structured_scopes", fake_fetch)

    asyncio.run(cli._refresh_h1_scopes(reg, ["acme", "manual"]))

    acme = reg.get("acme")
    assert acme.in_scope == ["*.acme.com", "api.acme.com"]  # refreshed from H1
    assert acme.out_of_scope == ["admin.acme.com"]
    assert reg.get("manual").in_scope == ["m.com"]          # no handle -> untouched


def test_refresh_h1_scopes_keeps_saved_scope_on_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))  # never touch the real config
    monkeypatch.setenv("H1_IDENTIFIER", "id")
    monkeypatch.setenv("H1_API_KEY", "key")
    from harness.programs import Program, Registry
    reg = Registry()
    reg.add(Program(name="acme", in_scope=["saved.acme.com"], h1_handle="acme"))

    import recon_orchestrator.hackerone_scope as h1

    async def boom(handle, identifier, token, **k):
        raise RuntimeError("api down")
    monkeypatch.setattr(h1, "fetch_structured_scopes", boom)

    asyncio.run(cli._refresh_h1_scopes(reg, ["acme"]))
    assert reg.get("acme").in_scope == ["saved.acme.com"]   # kept, no crash


def test_refresh_h1_scopes_without_creds_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))  # never touch the real config
    monkeypatch.delenv("H1_IDENTIFIER", raising=False)
    monkeypatch.delenv("H1_API_KEY", raising=False)
    from harness.programs import Program, Registry
    reg = Registry()
    reg.add(Program(name="acme", in_scope=["saved"], h1_handle="acme"))

    import recon_orchestrator.hackerone_scope as h1

    async def boom(*a, **k):
        raise AssertionError("must not hit the API without credentials")
    monkeypatch.setattr(h1, "fetch_structured_scopes", boom)

    asyncio.run(cli._refresh_h1_scopes(reg, ["acme"]))
    assert reg.get("acme").in_scope == ["saved"]


def test_auto_refreshes_h1_scope_before_the_pipeline(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))
    from harness.programs import Program, Registry
    reg = Registry()
    reg.add(Program(name="p", in_scope=["p.com"], seeds=["p.com"], h1_handle="p"))
    reg.save(tmp_path / "programs.yaml")

    async def _ok(*a, **k):
        return None
    monkeypatch.setattr(cli, "_ensure_cve_index_running", _ok)
    monkeypatch.setattr(cli, "_ensure_cve_corpus", _ok)
    monkeypatch.setattr(cli, "_teardown_services", lambda **k: None)

    order: list[str] = []

    async def fake_refresh(registry, names):
        order.append("refresh")

    async def fake_pipeline(registry, names):
        order.append("pipeline")
    monkeypatch.setattr(cli, "_refresh_h1_scopes", fake_refresh)
    monkeypatch.setattr(cli, "_run_pipeline", fake_pipeline)

    cli._cmd_auto(argparse.Namespace())
    assert order == ["refresh", "pipeline"]  # scope refreshed BEFORE recon


# --- per-program config an agent can set from a program's requirements --------

def test_set_header_persists_a_program_header(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))
    from harness.programs import Program, Registry
    reg = Registry()
    reg.add(Program(name="clear", in_scope=["clearme.com"], seeds=["clearme.com"]))
    reg.save(tmp_path / "programs.yaml")

    cli._cmd_set_header(argparse.Namespace(
        program="clear", name="X-Bug-Bounty", value="HackerOne-88yk"))

    p = Registry.load(tmp_path / "programs.yaml").get("clear")
    assert p.extra_headers == {"X-Bug-Bounty": "HackerOne-88yk"}


def test_set_header_unknown_program_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))
    import pytest
    with pytest.raises(SystemExit):
        cli._cmd_set_header(argparse.Namespace(
            program="nope", name="X", value="y"))


def test_show_policy_prints_the_fetched_policy(monkeypatch, capsys):
    monkeypatch.setenv("H1_IDENTIFIER", "id")
    monkeypatch.setenv("H1_API_KEY", "key")
    monkeypatch.setattr(cli, "_fetch_h1_policy",
                        lambda handle, ident, tok: "POLICY-FOR-" + handle)
    cli._cmd_show_policy(argparse.Namespace(handle="clear"))
    assert "POLICY-FOR-clear" in capsys.readouterr().out


# --- seed the practice targets ------------------------------------------------

def test_seed_practice_adds_the_vulnweb_program(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))
    from harness.programs import Registry

    cli._cmd_seed_practice(argparse.Namespace())

    reg = Registry.load(tmp_path / "programs.yaml")
    assert "vulnweb" in reg.names()
    vw = reg.get("vulnweb")
    assert vw.mode == "practice"
    assert len(vw.seeds) >= 3          # "at least 3" different sites
    assert "testphp.vulnweb.com" in vw.seeds


def test_seed_practice_is_idempotent_and_keeps_existing_programs(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path))
    from harness.programs import Program, Registry

    reg = Registry()
    reg.add(Program(name="mine", in_scope=["*.mine.com"], seeds=["mine.com"]))
    reg.save(tmp_path / "programs.yaml")

    cli._cmd_seed_practice(argparse.Namespace())
    cli._cmd_seed_practice(argparse.Namespace())  # second run must not duplicate/crash

    reg = Registry.load(tmp_path / "programs.yaml")
    assert "mine" in reg.names()               # existing program untouched
    assert reg.names().count("vulnweb") == 1   # added once, not duplicated
