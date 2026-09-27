"""Test isolation guard.

A test once wrote to the real ``~/.harness/programs.yaml`` because it didn't
redirect the config dir. This autouse fixture points HARNESS_HOME and
HARNESS_HUNTS at a per-test temp dir for EVERY test, so no test can ever read or
clobber the operator's real programs or hunt data — even if it forgets to.
A test that needs its own location just calls ``monkeypatch.setenv`` again.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_harness_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path / "hunts"))
