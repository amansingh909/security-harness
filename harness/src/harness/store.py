"""Persist per-program hunt results (the recon candidate leads)."""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from .paths import hunts_dir


def _program_dir(name: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
    return hunts_dir() / safe


def leads_path(name: str) -> Path:
    return _program_dir(name) / "leads.json"


def save_leads(name: str, leads: list[dict]) -> Path:
    path = leads_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "program": name,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "count": len(leads),
        "leads": leads,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_leads(name: str) -> list[dict]:
    path = leads_path(name)
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("leads", [])


def last_run(name: str) -> _dt.datetime | None:
    path = leads_path(name)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return _dt.datetime.fromisoformat(data["generated_at"])
    except (json.JSONDecodeError, KeyError, ValueError):
        return None
