"""Program registry: define a bug-bounty program once (scope + seeds), reuse it.

Persisted as YAML so it's human-editable outside the TUI too."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field


class Program(BaseModel):
    name: str
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    seeds: list[str] = Field(default_factory=list)
    seeds_file: str | None = None
    cve_index_url: str | None = None
    requests_per_second: float = 2.0
    allow_multilevel_wildcard: bool = True
    # Active testing — OWNED ASSETS ONLY, per program so it can never be a
    # global switch. active_tests turns on crafted-input probing; use_zap
    # routes it through OWASP ZAP (creds come from the environment).
    active_tests: bool = False
    use_zap: bool = False
    # Autonomous run mode. "real" = passive GET/HEAD recon only, never attack
    # traffic (real in-scope programs). "practice" = arm the active engine, for
    # intentionally-vulnerable practice targets you own or are meant to exploit.
    mode: Literal["real", "practice"] = "real"
    notes: str = ""

    def is_runnable(self) -> tuple[bool, str]:
        if not self.in_scope:
            return False, "no in-scope entries set"
        if not self.seeds and not self.seeds_file:
            return False, "no seeds or seeds_file set"
        return True, "ok"


class Registry:
    def __init__(self, programs: dict[str, Program] | None = None) -> None:
        self.programs: dict[str, Program] = programs or {}

    @classmethod
    def load(cls, path: Path) -> "Registry":
        if not path.exists():
            return cls({})
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw = data.get("programs", {})
        programs = {}
        for name, cfg in raw.items():
            cfg = dict(cfg or {})
            cfg.pop("name", None)
            programs[name] = Program(name=name, **cfg)
        return cls(programs)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        out = {
            "programs": {
                name: {k: v for k, v in prog.model_dump().items() if k != "name"}
                for name, prog in sorted(self.programs.items())
            }
        }
        path.write_text(yaml.safe_dump(out, sort_keys=False), encoding="utf-8")

    def add(self, program: Program) -> None:
        self.programs[program.name] = program

    def get(self, name: str) -> Program | None:
        return self.programs.get(name)

    def remove(self, name: str) -> bool:
        return self.programs.pop(name, None) is not None

    def names(self) -> list[str]:
        return sorted(self.programs)
