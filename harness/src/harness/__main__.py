"""`harness` entrypoint.

No args           -> launch the TUI.
harness list      -> list programs.
harness add ...   -> define a program without the TUI.
harness hunt NAME -> run recon headless and print a summary (CLI fallback).
"""
from __future__ import annotations

import argparse
import asyncio
import json

from . import engine, store
from .paths import ensure_dirs, programs_file
from .programs import Program, Registry


def _cmd_list(args: argparse.Namespace) -> None:
    reg = Registry.load(programs_file())
    if not reg.names():
        print("no programs yet. Add one: harness add <name> --scope '*.example.com' --seed www.example.com")
        return
    for name in reg.names():
        prog = reg.get(name)
        n = len(store.load_leads(name))
        print(f"{name:20} scope={prog.in_scope} seeds={len(prog.seeds)} leads={n}")


def _cmd_add(args: argparse.Namespace) -> None:
    ensure_dirs()
    reg = Registry.load(programs_file())
    reg.add(Program(
        name=args.name,
        in_scope=args.scope or [],
        out_of_scope=args.out or [],
        seeds=args.seed or [],
        seeds_file=args.seeds_file,
        cve_index_url=args.cve_index_url,
    ))
    reg.save(programs_file())
    print(f"added program '{args.name}'")


def _cmd_hunt(args: argparse.Namespace) -> None:
    reg = Registry.load(programs_file())
    program = reg.get(args.name)
    if program is None:
        raise SystemExit(f"unknown program '{args.name}' (see: harness list)")
    runnable, why = program.is_runnable()
    if not runnable:
        raise SystemExit(f"program not runnable: {why}")
    leads = asyncio.run(engine.run_recon(program))
    path = store.save_leads(program.name, leads)
    print(json.dumps({"program": program.name, "leads": len(leads), "saved": str(path)}))
    for lead in leads[:10]:
        print(f"  [{lead['priority_score']}] {lead['host']}  "
              f"{'; '.join(lead.get('signals', []))[:70]}")


def _cmd_tui(args: argparse.Namespace) -> None:
    from .tui.app import HarnessApp

    HarnessApp().run()


def main() -> None:
    parser = argparse.ArgumentParser(prog="harness",
                                     description="security-harness control TUI/CLI")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("tui", help="launch the TUI (default)").set_defaults(func=_cmd_tui)
    sub.add_parser("list", help="list programs").set_defaults(func=_cmd_list)

    p_add = sub.add_parser("add", help="define a program")
    p_add.add_argument("name")
    p_add.add_argument("--scope", action="append", help="in-scope entry (repeatable)")
    p_add.add_argument("--out", action="append", help="out-of-scope entry (repeatable)")
    p_add.add_argument("--seed", action="append", help="seed host (repeatable)")
    p_add.add_argument("--seeds-file", dest="seeds_file")
    p_add.add_argument("--cve-index-url", dest="cve_index_url")
    p_add.set_defaults(func=_cmd_add)

    p_hunt = sub.add_parser("hunt", help="run recon for a program (headless)")
    p_hunt.add_argument("name")
    p_hunt.set_defaults(func=_cmd_hunt)

    args = parser.parse_args()
    if not getattr(args, "command", None):
        _cmd_tui(args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
