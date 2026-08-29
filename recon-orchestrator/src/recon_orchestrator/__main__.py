"""CLI entrypoint: run authorized recon against configured scope + seeds."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .config import get_settings
from .logging_config import configure_logging
from .orchestrator import run_recon
from .scope import ScopeGuard


def _load_scope_file(path: str) -> tuple[list[str], list[str]]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        import yaml
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return data.get("in_scope", []), data.get("out_of_scope", [])


def _load_seeds_file(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def _cmd_run(args: argparse.Namespace) -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json, settings.service_name)

    in_scope = settings.in_scope_list()
    out_scope = settings.out_of_scope_list()
    if settings.scope_file:
        f_in, f_out = _load_scope_file(settings.scope_file)
        in_scope += f_in
        out_scope += f_out

    if not in_scope:
        print("error: no in-scope entries. Set RECON_IN_SCOPE or RECON_SCOPE_FILE. "
              "Recon refuses to run without an explicit authorized scope.",
              file=sys.stderr)
        raise SystemExit(2)

    scope = ScopeGuard(in_scope, out_scope, settings.allow_multilevel_wildcard)

    seeds = settings.seed_list()
    if settings.seeds_file:
        seeds += _load_seeds_file(settings.seeds_file)
    if args.seed:
        seeds += args.seed
    if not seeds:
        print("error: no seed hosts. Set RECON_SEEDS / RECON_SEEDS_FILE or pass --seed.",
              file=sys.stderr)
        raise SystemExit(2)

    findings = asyncio.run(run_recon(settings, scope, seeds))
    output = json.dumps({"count": len(findings), "candidates": findings}, indent=2)
    if settings.out_file:
        with open(settings.out_file, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(json.dumps({"count": len(findings), "out": settings.out_file}))
    else:
        print(output)


def main() -> None:
    parser = argparse.ArgumentParser(prog="recon-orchestrator")
    sub = parser.add_subparsers(dest="command", required=True)
    p_run = sub.add_parser("run", help="run authorized recon")
    p_run.add_argument("--seed", action="append", help="add a seed host (repeatable)")
    p_run.set_defaults(func=_cmd_run)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
