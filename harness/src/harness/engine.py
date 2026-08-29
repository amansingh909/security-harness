"""Glue between the TUI and the harness components.

Imports are lazy so the TUI still launches if a component isn't installed yet;
each function raises a clear, catchable error the UI can surface instead."""
from __future__ import annotations

from .programs import Program


class ComponentMissing(RuntimeError):
    """A required sibling component isn't importable/installed."""


async def run_recon(program: Program) -> list[dict]:
    """Run recon for a program via recon_orchestrator; return candidate leads."""
    try:
        from recon_orchestrator.config import Settings
        from recon_orchestrator.orchestrator import run_recon as _run
        from recon_orchestrator.scope import ScopeGuard
    except ImportError as exc:  # pragma: no cover - env dependent
        raise ComponentMissing(
            "recon-orchestrator not installed. Run: pip install -e ../recon-orchestrator"
        ) from exc

    seeds = list(program.seeds)
    if program.seeds_file:
        try:
            with open(program.seeds_file, encoding="utf-8") as fh:
                seeds += [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except OSError as exc:
            raise ComponentMissing(f"seeds_file unreadable: {exc}") from exc

    settings = Settings(
        requests_per_second=program.requests_per_second,
        cve_index_url=program.cve_index_url,
    )
    scope = ScopeGuard(
        program.in_scope, program.out_of_scope, program.allow_multilevel_wildcard
    )
    return await _run(settings, scope, seeds)


async def search_cve(query: str, cve_index_url: str, k: int = 10) -> list[dict]:
    """Query a running cve-index API for CVEs/techniques."""
    import httpx

    async with httpx.AsyncClient(base_url=cve_index_url, timeout=15) as client:
        resp = await client.get("/search", params={"q": query, "k": k})
        resp.raise_for_status()
        return resp.json().get("results", [])
