"""CLI: render a structured finding file into report artifacts."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .config import get_settings
from .generator import generate
from .logging_config import configure_logging
from .models import Finding


def _load_finding(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError:  # pragma: no cover
            print("PyYAML not installed; use a .json finding or `pip install pyyaml`",
                  file=sys.stderr)
            raise
        return yaml.safe_load(text)
    return json.loads(text)


def _cmd_render(args: argparse.Namespace) -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json, settings.service_name)
    try:
        finding = Finding.from_dict(_load_finding(args.finding))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)

    report = generate(finding)

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        base = os.path.join(args.out, report.fingerprint)
        with open(f"{base}.md", "w", encoding="utf-8") as fh:
            fh.write(report.markdown)
        with open(f"{base}.hackerone.json", "w", encoding="utf-8") as fh:
            json.dump(report.hackerone, fh, indent=2)
        with open(f"{base}.bugcrowd.json", "w", encoding="utf-8") as fh:
            json.dump(report.bugcrowd, fh, indent=2)
        print(json.dumps({"fingerprint": report.fingerprint, "rating": report.rating,
                          "cvss": report.cvss_score, "out": args.out}))
        return

    if args.format == "markdown":
        print(report.markdown)
    elif args.format == "hackerone":
        print(json.dumps(report.hackerone, indent=2))
    elif args.format == "bugcrowd":
        print(json.dumps(report.bugcrowd, indent=2))
    else:  # all
        print(json.dumps({
            "fingerprint": report.fingerprint,
            "cvss_score": report.cvss_score,
            "rating": report.rating,
            "markdown": report.markdown,
            "hackerone": report.hackerone,
            "bugcrowd": report.bugcrowd,
        }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="bounty-reporter")
    sub = parser.add_subparsers(dest="command", required=True)
    p_render = sub.add_parser("render", help="finding file -> report artifacts")
    p_render.add_argument("finding", help="path to a .json / .yaml finding file")
    p_render.add_argument("--format", choices=["markdown", "hackerone", "bugcrowd", "all"],
                          default="all")
    p_render.add_argument("--out", help="write artifacts to this directory")
    p_render.set_defaults(func=_cmd_render)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
