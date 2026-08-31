"""Regression tests for the `harness` CLI entrypoint.

Every test here pins a bug that actually shipped. `__main__.py` had no coverage,
which is how a `store.Registry` that does not exist and a relative import that
escapes the package both survived into a release.
"""
from __future__ import annotations

import os

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
