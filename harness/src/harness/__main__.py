"""`harness` entrypoint.

No args           -> launch the TUI.
harness list      -> list programs.
harness add ...   -> define a program without the TUI.
harness hunt NAME -> run recon headless and print a summary (CLI fallback).
harness global    -> run nightly pipeline for all programs, open Triage dashboard,
                     generate reports, and optionally upload.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import time
from getpass import getpass
from pathlib import Path

from . import engine, store
from .paths import config_dir, ensure_dirs, programs_file
from .programs import Program, Registry

def _cve_index_dir() -> str:
    """Directory holding the cve-index compose file and its poetry project.

    Derived from this package's location so a moved or renamed checkout still
    works; HARNESS_REPO overrides it, and the historical path is the fallback
    for a non-editable install.
    """
    override = os.environ.get("HARNESS_REPO")
    if override:
        return os.path.join(override, "cve-index")
    # .../<repo>/harness/src/harness/__main__.py -> .../<repo>
    repo = Path(__file__).resolve().parents[3]
    candidate = repo / "cve-index"
    if candidate.is_dir():
        return str(candidate)
    return os.path.expanduser("~/security-harness/cve-index")


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
    """Original add command – kept for compatibility (full CLI syntax)."""
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

def _cmd_add_prog(args: argparse.Namespace) -> None:
    """Quick add a program with name, scope, and comma‑separated seeds."""
    ensure_dirs()
    reg = Registry.load(programs_file())
    # Split seeds string by commas, strip whitespace, ignore empty parts
    seed_list = [s.strip() for s in args.seeds.split(",") if s.strip()]
    # Split scope string by commas into a list of patterns
    scope_list = [s.strip() for s in args.scope.split(",") if s.strip()]
    reg.add(Program(
        name=args.name,
        in_scope=scope_list,
        out_of_scope=[],         # keep empty; user can specify via --out if needed
        seeds=seed_list,
        seeds_file=None,
        cve_index_url=args.cve_index_url,
    ))
    reg.save(programs_file())
    print(f"added program '{args.name}' (scope={scope_list}, seeds={seed_list})")

def _cmd_import_scope(args: argparse.Namespace) -> None:
    """Pull a program's scope from HackerOne into programs.yaml.

    Reads a JSON export with --file, otherwise hits the API using the
    credentials in ~/.harness/.env.
    """
    try:
        from recon_orchestrator.hackerone_scope import (
            fetch_structured_scopes, parse_hackerone_scope,
        )
    except ImportError as exc:
        raise SystemExit(
            f"recon-orchestrator not installed: {exc}\n"
            "  pip install -e ../recon-orchestrator"
        )

    skipped: list[str] = []
    if args.file:
        in_scope, out_of_scope = parse_hackerone_scope(args.file, skipped)
        source = args.file
    else:
        identifier = os.getenv("H1_IDENTIFIER")
        token = os.getenv("H1_API_KEY")
        if not identifier or not token:
            raise SystemExit(
                "set H1_IDENTIFIER and H1_API_KEY in ~/.harness/.env, or pass --file"
            )
        try:
            in_scope, out_of_scope = asyncio.run(
                fetch_structured_scopes(args.handle, identifier, token,
                                        skipped=skipped)
            )
        except (PermissionError, LookupError, ValueError) as exc:
            raise SystemExit(str(exc))
        source = f"api.hackerone.com ({args.handle})"

    if not in_scope and not out_of_scope:
        raise SystemExit(f"no host-shaped assets found in {source}")

    print(f"scope from {source}:")
    for pattern in in_scope:
        print(f"  in  {pattern}")
    for pattern in out_of_scope:
        print(f"  out {pattern}")
    if skipped:
        # Real scope entries that are not whole hosts (repos, app ids,
        # path-scoped URLs). Reducing them to a host would over-broaden
        # scope, so they are listed for a human instead.
        print(f"\n  {len(skipped)} entr(ies) not host-shaped, review by hand:")
        for item in skipped:
            print(f"    - {item}")

    name = args.program or args.handle
    ensure_dirs()
    reg = Registry.load(programs_file())
    existing = reg.get(name)
    if existing is None:
        # Seed with the concrete hosts; wildcards cannot be probed directly.
        seeds = [p for p in in_scope if not p.startswith("*")]
        reg.add(Program(
            name=name, in_scope=in_scope, out_of_scope=out_of_scope,
            seeds=seeds, seeds_file=None,
            cve_index_url=args.cve_index_url,
        ))
        print(f"\ncreated program {name!r} with {len(seeds)} seed(s)")
    else:
        # Only the scope is refreshed; seeds and tuning stay as the user set them.
        updated = existing.model_copy(update={
            "in_scope": in_scope, "out_of_scope": out_of_scope,
        })
        reg.add(updated)
        print(f"\nupdated scope for existing program {name!r} (seeds untouched)")
    reg.save(programs_file())


def _cmd_preview(args: argparse.Namespace) -> None:
    """Set up an active-testing program pointed at a Vercel PREVIEW deployment.

    Pass a preview URL directly, or a project name (resolved via VERCEL_TOKEN).
    The program is scoped to that one exact host and armed with active_tests +
    ZAP — so you attack the preview, never prod.
    """
    from .vercel import host_from_url, latest_preview_host

    host = host_from_url(args.target)
    project = None
    if host is None:
        # Not a URL — treat as a Vercel project name and resolve via the API.
        project = args.target
        token = os.getenv("VERCEL_TOKEN")
        if not token:
            raise SystemExit(
                f"'{args.target}' is not a URL and no VERCEL_TOKEN is set.\n"
                "  Paste a preview URL, or add VERCEL_TOKEN to ~/.harness/.env\n"
                "  (create one at vercel.com/account/tokens)."
            )
        try:
            host = asyncio.run(latest_preview_host(args.target, token))
        except (PermissionError, LookupError, RuntimeError) as exc:
            raise SystemExit(str(exc))

    if host in ("vercel.app",):
        raise SystemExit(f"refusing: {host!r} does not look like a preview host")

    # A project resolves to a STABLE name so re-running after a new deploy
    # updates the same program (and re-targets the latest preview) rather than
    # piling up one program per deployment hash.
    name = args.program or (f"{project}-preview" if project
                            else host.split(".")[0] + "-preview")
    ensure_dirs()
    reg = Registry.load(programs_file())
    existing = reg.get(name)
    fields = {
        "in_scope": [host],
        "out_of_scope": [],
        "seeds": [host],
        "active_tests": True,
        "use_zap": args.zap,
    }
    if existing is None:
        reg.add(Program(name=name, seeds_file=None,
                        cve_index_url=args.cve_index_url, **fields))
        verb = "created"
    else:
        reg.add(existing.model_copy(update=fields))
        verb = "updated"
    reg.save(programs_file())

    engine = "ZAP" if args.zap else "built-in"
    print(f"{verb} program {name!r} -> {host}")
    print(f"  scope: {host} (exact host only)   active testing: {engine}")
    print(f"  run it:  harness hunt {name}     or press 'r' on {name!r} in the TUI")
    print("  NOTE: preview deployments with Vercel auth protection must have it "
          "disabled (or a bypass) for the scan to reach them.")


def _cmd_up(args: argparse.Namespace) -> None:
    """Start Elasticsearch and cve‑index services and verify health."""
    # Run the async helper that starts services and waits for health
    try:
        asyncio.run(_ensure_cve_index_running())
        print("✅ Services are up and healthy.")
    except Exception as exc:
        print(f"❌ Failed to start services: {exc}")

def _cmd_down(args: argparse.Namespace) -> None:
    """Stop cve‑index server and bring down Elasticsearch."""
    pid_path = Path(os.path.expanduser("~/.cve_index_pid"))
    stopped = False
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text().strip() or 0)
        except (OSError, ValueError) as exc:
            print(f"⚠️  Could not read PID file: {exc}")
            pid = 0
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"🛑 Stopped cve-index (PID {pid}).")
                stopped = True
            except ProcessLookupError:
                print(f"⚠️  PID {pid} is not running — the file was stale.")
            except PermissionError:
                print(f"⚠️  Not permitted to signal PID {pid}.")
        # Either way the file no longer describes a live server.
        pid_path.unlink(missing_ok=True)

    if not stopped:
        # Only fall back to a pattern kill if the PID route did not work. The
        # pattern is anchored on the console-script path so it cannot match an
        # editor or shell that merely has the words on its command line.
        killed = subprocess.run(
            ["pkill", "-f", r"bin/cve-index serve$"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if killed.returncode == 0:
            print("🛑 Stopped cve-index via pattern match.")
        else:
            print("ℹ️  No running cve-index process found.")

    # Bring down Elasticsearch
    compose = subprocess.run(
        ["docker", "compose", "down"], cwd=_cve_index_dir(),
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    if compose.returncode == 0:
        print("🧹 Docker compose stack brought down.")
    else:
        err = compose.stderr.decode(errors="replace").strip().splitlines()
        print(f"⚠️  docker compose down failed: {err[-1] if err else 'unknown error'}")


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


def _cmd_scan(args: argparse.Namespace) -> None:
    """Run recon and scan for vulnerabilities (headless)."""
    reg = Registry.load(programs_file())
    program = reg.get(args.name)
    if program is None:
        raise SystemExit(f"unknown program '{args.name}' (see: harness list)")
    runnable, why = program.is_runnable()
    if not runnable:
        raise SystemExit(f"program not runnable: {why}")

    # Run reconnaissance first
    leads = asyncio.run(engine.run_recon(program))

    # Then scan for vulnerabilities
    vulns = asyncio.run(engine.scan_for_vulns(program, leads))

    # Output results
    print(json.dumps({
        "program": program.name,
        "leads": len(leads),
        "vulnerabilities": len(vulns),
        "vuln_details": vulns
    }, indent=2))

    # Also print a summary to stdout
    if vulns:
        print(f"\nFound {len(vulns)} potential vulnerabilities:")
        for vuln in vulns[:5]:  # Show first 5
            print(f"  [{vuln.get('priority_score', 0)}] {vuln['host']}:{vuln['service'].get('port', '?')}")
            if vuln.get('cves'):
                print(f"    CVEs: {', '.join([c.get('id', 'unknown') for c in vuln['cves'][:3]])}")
    else:
        print("\nNo vulnerabilities found via CVE index scan.")


def _load_env_file() -> None:
    """Load KEY=VALUE lines from ~/.harness/.env into the environment.

    Kept outside the repo on purpose so API tokens can never be committed.
    Values already set in the real environment win, so an explicit
    `H1_API_KEY=... harness global` still overrides the file.
    """
    env_path = config_dir() / ".env"
    try:
        text = env_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    except OSError as exc:
        print(f"⚠️  Could not read {env_path}: {exc}")
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


async def _cve_index_healthy(url: str = "http://localhost:8080") -> bool:
    """True if the cve-index API answers its health endpoint."""
    try:
        return bool((await engine.cve_index_health(url)).get("up", False))
    except Exception:
        # Connection refused / timeout while the service is coming up is expected.
        return False


async def _ensure_cve_index_running() -> None:
    """Ensure Elasticsearch and the cve-index FastAPI are running.
    Starts them if needed (docker compose up -d elasticsearch, then cve-index serve).
    Waits until the health endpoint returns success.
    """
    global _cve_index_server_proc

    # If something is already serving, adopt it. Checking a module-level variable
    # is useless across processes — it is always unset in a fresh `harness` run,
    # so `harness up` followed by `harness global` used to spawn a second server
    # and overwrite the PID file, orphaning the first one.
    if await _cve_index_healthy():
        return

    # Start ES via compose (idempotent)
    try:
        subprocess.run(
            ["docker", "compose", "up", "-d", "elasticsearch"],
            cwd=_cve_index_dir(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        print("⚠️  docker not found — assuming Elasticsearch is managed elsewhere.")
    except OSError as exc:
        print(f"⚠️  Could not run docker compose: {exc}")

    # Start the FastAPI server in the background.
    try:
        _cve_index_server_proc = subprocess.Popen(
            ["poetry", "run", "cve-index", "serve"],
            cwd=_cve_index_dir(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Store the pid so `harness down` can stop it later
        with open(os.path.expanduser("~/.cve_index_pid"), "w") as f:
            f.write(str(_cve_index_server_proc.pid))
    except FileNotFoundError:
        raise RuntimeError(
            "`poetry` not found — cannot start cve-index. Install poetry or start "
            "the service manually."
        ) from None
    except OSError as exc:
        raise RuntimeError(f"Could not launch cve-index serve: {exc}") from exc

    # Wait for health endpoint to succeed, with timeout.
    deadline = time.time() + 30.0  # 30 seconds total wait
    while time.time() < deadline:
        if await _cve_index_healthy():
            return
        # Fail fast if the server we just launched has already exited, rather
        # than sitting out the full timeout.
        if _cve_index_server_proc.poll() is not None:
            raise RuntimeError(
                f"cve-index serve exited immediately (code "
                f"{_cve_index_server_proc.returncode}). Run it directly in "
                f"{_cve_index_dir()} to see the error."
            )
        await asyncio.sleep(1.0)
    raise RuntimeError("cve-index service did not become healthy within 30s")


async def _run_pipeline(registry: Registry, names: list[str]) -> None:
    """Recon + vuln scan for every program, in a single event loop.

    Prints progress as it goes: this stage can take a while and used to run in
    total silence, which is indistinguishable from a hang.
    """
    total = len(names)
    for i, prog_name in enumerate(names, 1):
        program = registry.get(prog_name)
        tag = f"[{i}/{total}] {prog_name}"
        try:
            print(f"→ {tag}: recon over {len(program.seeds)} seed(s)…", flush=True)
            t0 = time.monotonic()
            leads = await engine.run_recon(program)
            store.save_leads(prog_name, leads)
            print(f"  {tag}: {len(leads)} lead(s) in {time.monotonic() - t0:.1f}s")
        except Exception as exc:
            print(f"❌ {tag}: recon failed: {exc}")
            continue
        try:
            print(f"→ {tag}: scanning for vulnerabilities…", flush=True)
            t0 = time.monotonic()
            vulns = await engine.scan_for_vulns(program, leads)
            store.save_vulns(prog_name, vulns)
            print(f"  {tag}: {len(vulns)} vuln(s) in {time.monotonic() - t0:.1f}s")
        except Exception as exc:
            print(f"❌ {tag}: scan failed: {exc}")


def _cmd_global(args: argparse.Namespace) -> None:
    """
    One-shot command that:
    0️⃣ Ensures the CVE‑index services are running (starts them if needed).
    1️⃣ Executes the nightly orchestrator for *all* programs (sub‑domain enum,
       port sweep, CPE‑based CVE lookup, sensitive‑path checks, scope import).
    2️⃣ Immediately opens the Triage dashboard so the user can review the
       ranked findings.
    3️⃣ Generates a consolidated markdown/JSON report for each program.
    4️⃣ (Optional) Uploads those reports to HackerOne / Bugcrowd. Keys come from
       ~/.harness/.env or the environment; otherwise you are prompted once.
    """
    # 0️⃣ Ensure services are up
    print("→ checking cve-index services…")
    try:
        asyncio.run(_ensure_cve_index_running())
    except Exception as exc:
        print(f"❌ Failed to start cve-index services: {exc}")
        print("    You may need to start Docker and/or install the cve-index CLI.")
        return

    # 1️⃣ Run nightly recon & vuln scan for all programs, in one event loop.
    registry = Registry.load(programs_file())
    names = registry.names()
    if not names:
        print("no programs defined — add one with `harness add-prog NAME SCOPE SEEDS`.")
        return
    asyncio.run(_run_pipeline(registry, names))

    # 2️⃣ Open triage UI (same as pressing `t` in the interactive TUI)
    os.environ["HARNESS_AUTO_OPEN_TRIAGE"] = "1"
    from .tui.app import HarnessApp
    HarnessApp().run()

    # 3️⃣ After the UI exits, generate batch reports for each program.
    from .paths import hunts_dir

    # Keys come from ~/.harness/.env or the environment; getpass so a typed
    # token is not echoed to the terminal or left sitting in scrollback.
    h1_key = os.getenv("H1_API_KEY") or getpass("HackerOne API key (leave blank to skip): ").strip()
    bc_key = os.getenv("BC_API_KEY") or getpass("Bugcrowd API key (leave blank to skip): ").strip()

    for prog_name in registry.names():
        vulns = store.load_vulns(prog_name)
        if not vulns:
            print(f"⚠️ No vulns for program {prog_name!r} – skipping report.")
            continue
        out_dir = hunts_dir() / prog_name
        try:
            md_path = engine.render_batch_report(prog_name, vulns, out_dir)
            print(f"📄 Report for {prog_name!r} written to: {md_path}")
        except Exception as exc:  # pragma: no cover
            print(f"❌ Failed to render report for {prog_name!r}: {exc}")
            continue

        # 4️⃣ Upload if keys are supplied
        if h1_key or bc_key:
            # This submits real reports to a real program under the user's own
            # account and cannot be undone, so confirm per program first.
            targets = ", ".join(
                n for n, k in (("HackerOne", h1_key), ("Bugcrowd", bc_key)) if k
            )
            answer = input(
                f"Submit {len(vulns)} finding(s) for {prog_name!r} to {targets}? [y/N] "
            ).strip().lower()
            if answer not in ("y", "yes"):
                print(f"   skipped upload for {prog_name!r}.")
                continue
            try:
                # bounty_reporter is a sibling top-level package, not a submodule
                # of harness — a relative import escapes the package and fails.
                from bounty_reporter.uploader import upload_report
                # render_batch_report returns the Markdown path, but upload_report
                # parses JSON. Both are written side by side in out_dir.
                json_path = md_path.with_suffix(".json")
                res = upload_report(json_path, prog_name, h1_key or None, bc_key or None)
                print(f"📤 Upload result for {prog_name!r}: {res}")
            except Exception as exc:  # pragma: no cover
                print(f"❌ Upload failed for {prog_name!r}: {exc}")


def _cmd_tui(args: argparse.Namespace) -> None:
    from .tui.app import HarnessApp

    HarnessApp().run()


def main() -> None:
    _load_env_file()
    parser = argparse.ArgumentParser(prog="harness",
                                     description="security-harness control TUI/CLI")
    sub = parser.add_subparsers(dest="command")

    # ── Core commands ────────────────────────────────────────────────────────
    sub.add_parser("tui", help="launch the TUI (default)").set_defaults(func=_cmd_tui)
    sub.add_parser("list", help="list programs").set_defaults(func=_cmd_list)

    # ── Existing add (full CLI syntax) ────────────────────────────────────────
    p_add = sub.add_parser("add", help="define a program (full CLI syntax)")
    p_add.add_argument("name")
    p_add.add_argument("--scope", action="append", help="in-scope entry (repeatable)")
    p_add.add_argument("--out", action="append", help="out-of-scope entry (repeatable)")
    p_add.add_argument("--seed", action="append", help="seed host (repeatable)")
    p_add.add_argument("--seeds-file", dest="seeds_file")
    p_add.add_argument("--cve-index-url", dest="cve_index_url")
    p_add.set_defaults(func=_cmd_add)

    # ── New concise add‑prog command (name scope seeds) ───────────────────────
    p_addprog = sub.add_parser("add-prog", help="quick add a program (name, scope, comma‑separated seeds)")
    p_addprog.add_argument("name", help="program identifier")
    p_addprog.add_argument("scope", help="in‑scope wildcard, e.g. \"*.example.com\"")
    p_addprog.add_argument("seeds", help="comma‑separated seed hosts, e.g. \"www.example.com,api.example.com\"")
    p_addprog.add_argument("--cve-index-url", dest="cve_index_url", default="http://localhost:8080", help="URL of the local cve‑index API")
    p_addprog.set_defaults(func=_cmd_add_prog)

    # ── Hunt / Scan (headless) ────────────────────────────────────────────────
    p_hunt = sub.add_parser("hunt", help="run recon for a program (headless)")
    p_hunt.add_argument("name")
    p_hunt.set_defaults(func=_cmd_hunt)

    p_scan = sub.add_parser("scan", help="run recon and scan for vulnerabilities (headless)")
    p_scan.add_argument("name")
    p_scan.set_defaults(func=_cmd_scan)

    # ── Global pipeline ───────────────────────────────────────────────────────
    p_global = sub.add_parser("global", help="run nightly pipeline for all programs, open Triage dashboard, generate reports, and optionally upload")
    p_global.set_defaults(func=_cmd_global)

    # ── HackerOne scope import ────────────────────────────────────────────────
    p_scope = sub.add_parser(
        "import-scope",
        help="import a HackerOne program's scope into programs.yaml",
    )
    p_scope.add_argument("handle", help="HackerOne program handle, e.g. 'security'")
    p_scope.add_argument("--program", help="local program name (default: the handle)")
    p_scope.add_argument("--file", help="read a scope JSON export instead of the API")
    p_scope.add_argument("--cve-index-url", dest="cve_index_url",
                         default="http://localhost:8080")
    p_scope.set_defaults(func=_cmd_import_scope)

    # ── Vercel preview target (active testing, owned assets) ──────────────────
    p_prev = sub.add_parser(
        "preview",
        help="arm active testing against a Vercel PREVIEW deployment (not prod)",
    )
    p_prev.add_argument("target", help="a preview URL, or a Vercel project name (needs VERCEL_TOKEN)")
    p_prev.add_argument("--program", help="local program name (default: <host>-preview)")
    p_prev.add_argument("--zap", action="store_true", help="use the ZAP engine (default: built-in tester)")
    p_prev.add_argument("--cve-index-url", dest="cve_index_url", default="http://localhost:8080")
    p_prev.set_defaults(func=_cmd_preview)

    # ── Service helpers ───────────────────────────────────────────────────────
    sub.add_parser("up", help="start Elasticsearch and cve‑index services and verify health").set_defaults(func=_cmd_up)
    sub.add_parser("down", help="stop cve‑index server and bring down Elasticsearch").set_defaults(func=_cmd_down)

    args = parser.parse_args()
    if not getattr(args, "command", None):
        _cmd_tui(args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
