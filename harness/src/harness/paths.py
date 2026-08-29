"""Where the harness keeps its config and hunt results."""
from __future__ import annotations

import os
from pathlib import Path


def config_dir() -> Path:
    return Path(os.environ.get("HARNESS_HOME", str(Path.home() / ".harness")))


def hunts_dir() -> Path:
    return Path(os.environ.get("HARNESS_HUNTS", str(Path.home() / "hunts")))


def programs_file() -> Path:
    return config_dir() / "programs.yaml"


def ensure_dirs() -> None:
    config_dir().mkdir(parents=True, exist_ok=True)
    hunts_dir().mkdir(parents=True, exist_ok=True)
