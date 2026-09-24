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
                    "_cmd_down"):
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
