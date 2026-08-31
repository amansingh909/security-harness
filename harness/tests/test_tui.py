"""Regression tests for the TUI.

Two shipped bugs motivate this file:

* `TriageScreen` bound escape and q to `cancel`, but had no `action_cancel`.
  Textual had nothing to call, so the modal could not be closed at all — with
  `harness global` auto-opening it, the app was unusable.
* `PromptScreen`'s body had been moved inside a stray `main()`, leaving the
  class an empty stub, so the search and classify modals rendered blank.
"""
from __future__ import annotations

import ast
import importlib.util
import pathlib

import pytest
from textual.binding import Binding

import harness
from harness.tui.app import (
    AddProgramScreen,
    HarnessApp,
    PromptScreen,
    TriageScreen,
)

SCREENS = (AddProgramScreen, PromptScreen, TriageScreen, HarnessApp)


def test_every_binding_resolves_to_an_action():
    """A Binding naming a missing `action_*` fails silently — the key does
    nothing and Textual reports no error. This is the triage bug."""
    missing = []
    for screen in SCREENS:
        for binding in screen.BINDINGS:
            action = binding.action if isinstance(binding, Binding) else binding[1]
            # Actions may take arguments, e.g. "switch_screen('x')".
            name = action.split("(")[0].strip()
            if not hasattr(screen, f"action_{name}"):
                missing.append(f"{screen.__name__} binds to missing action_{name}")
    assert not missing, missing


@pytest.mark.parametrize("screen", SCREENS)
def test_screen_is_not_an_empty_stub(screen):
    """PromptScreen was reduced to a docstring when its body was moved."""
    assert hasattr(screen, "compose"), f"{screen.__name__} has no compose()"


def test_prompt_screen_takes_its_constructor_arguments():
    """Callers do PromptScreen(title, placeholder); the stub took neither."""
    prompt = PromptScreen("a title", "a placeholder")
    assert prompt._title == "a title"
    assert prompt._placeholder == "a placeholder"


@pytest.mark.asyncio
async def test_triage_opens_and_closes():
    app = HarnessApp()
    async with app.run_test() as pilot:
        await pilot.press("t")
        await pilot.pause()
        assert isinstance(app.screen, TriageScreen), "'t' did not open triage"

        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, TriageScreen), "escape did not close triage"

        await pilot.press("t")
        await pilot.pause()
        await pilot.press("q")
        await pilot.pause()
        assert not isinstance(app.screen, TriageScreen), "q did not close triage"


@pytest.mark.asyncio
async def test_auto_open_triage_env_var(monkeypatch):
    """`harness global` signals the TUI through HARNESS_AUTO_OPEN_TRIAGE."""
    monkeypatch.setenv("HARNESS_AUTO_OPEN_TRIAGE", "1")
    app = HarnessApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, TriageScreen)
        await pilot.press("escape")
        await pilot.pause()
    # The flag is consumed so a second app in the same process is unaffected.
    import os
    assert "HARNESS_AUTO_OPEN_TRIAGE" not in os.environ


def test_relative_imports_resolve():
    """`from ..bounty_reporter...` inside harness.tui.app resolves to
    `harness.bounty_reporter`, which does not exist. Both the CLI upload and
    the TUI upload shipped with this, and the TUI nightly run imported a
    `run_all_once` that was never written."""
    root = pathlib.Path(harness.__file__).parent
    failures = []
    for path in sorted(root.rglob("*.py")):
        parts = list(path.relative_to(root).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        # Package containing this module, as a dotted path.
        package = ".".join(["harness"] + parts[:-1]) if parts else "harness"
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.ImportFrom) or not node.level:
                continue
            base = package.split(".")
            climb = node.level - 1
            if climb > len(base) - 1:
                failures.append(f"{path.name}: {'.' * node.level}{node.module} escapes the package")
                continue
            target = base[: len(base) - climb] if climb else base
            resolved = ".".join(target + ([node.module] if node.module else []))
            try:
                found = importlib.util.find_spec(resolved) is not None
            except (ImportError, ModuleNotFoundError):
                found = False
            if not found:
                failures.append(f"{path.name}: {'.' * node.level}{node.module} -> {resolved} not importable")
    assert not failures, failures


def test_sibling_packages_the_tui_imports_lazily_are_available():
    """These are imported inside handlers, so a bad name only surfaces when
    the user presses the key."""
    for module in ("bounty_reporter.uploader", "recon_orchestrator.nightly"):
        assert importlib.util.find_spec(module) is not None, f"{module} not importable"


@pytest.mark.asyncio
async def test_scan_persists_findings_so_triage_can_show_them(monkeypatch, tmp_path):
    """The `v` scan computed findings but never saved them, so Triage (which
    reads from storage) was always empty.

    HARNESS_HUNTS is redirected to a temp dir so this never touches the real
    ~/hunts, and the program is added to an isolated HARNESS_HOME.
    """
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path / "hunts"))

    import harness.tui.app as appmod
    from harness import store
    from harness.programs import Program, Registry
    from harness.paths import ensure_dirs, programs_file

    ensure_dirs()
    reg = Registry()
    reg.add(Program(name="t", in_scope=["*.t.test"], seeds=["t.test"]))
    reg.save(programs_file())

    monkeypatch.setattr(appmod.engine, "run_recon",
                        lambda program: _async([{"host": "x", "priority_score": 5}]))
    monkeypatch.setattr(appmod.engine, "scan_for_vulns",
                        lambda program, leads: _async(
                            [{"host": "x", "service": {"host": "x", "port": 443},
                              "cves": [], "priority_score": 50}]))

    app = appmod.HarnessApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        app.current_program = "t"
        app._run_scan(app.registry.get("t"))
        for _ in range(20):
            await pilot.pause()
            if store.load_vulns("t"):
                break
        assert store.load_vulns("t"), "scan did not persist its findings"


async def _async(value):
    return value
