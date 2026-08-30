"""Nightly orchestrator skeleton.

Runs recon and vulnerability scanning for each defined program on a schedule.
All network interactions are GET/HEAD only and respect the program's authorized scope.
Results are persisted via the harness store module.
"""

import asyncio
import logging
from datetime import datetime
from typing import List

from ..src.harness.engine import run_recon, scan_for_vulns
from ..src.harness import store
from ..src.harness.programs import Registry, Program

log = logging.getLogger(__name__)

async def _process_program(program: Program) -> None:
    """Run recon and vulnerability scan for a single program.

    The function:
    1. Calls ``run_recon`` to obtain leads.
    2. Saves the leads via ``store.save_leads``.
    3. Calls ``scan_for_vulns`` to obtain CVE findings.
    4. Stores the findings back into the harness store (same location).
    All exceptions are logged; the scheduler continues with other programs.
    """
    try:
        log.info("[nightly] Starting recon for program %s", program.name)
        leads = await run_recon(program)
        store.save_leads(program.name, leads)
        vulns = await scan_for_vulns(program, leads)
        # store the vulns under a separate key – we reuse the same store API
        store.save_vulns(program.name, vulns)  # type: ignore[attr-defined]
        log.info("[nightly] Completed %s – %d leads, %d vulns", program.name, len(leads), len(vulns))
    except Exception as exc:  # noqa: BLE001
        log.error("[nightly] error processing program %s: %s", program.name, exc)

async def run_nightly(interval_seconds: int = 86400) -> None:
    """Run the nightly orchestrator continuously (default 24 h interval)."""
    """Main entry‑point for the nightly scheduler.

    ``interval_seconds`` defaults to 24 h. The coroutine runs forever; each loop
    loads the program registry, processes each program concurrently (max 5), then
    sleeps until the next interval.
    """
    registry = Registry.load(store.programs_file())
    while True:
        start = datetime.utcnow()
        log.info("[nightly] run started at %s", start.isoformat())
        programs: List[Program] = list(registry.values())
        # limit concurrency to avoid hammering the network
        semaphore = asyncio.Semaphore(5)
        async def _wrapper(p: Program) -> None:
            async with semaphore:
                await _process_program(p)
        await asyncio.gather(*[_wrapper(p) for p in programs])
        log.info("[nightly] run finished, sleeping %s seconds", interval_seconds)
        await asyncio.sleep(interval_seconds)

if __name__ == "__main__":
    # simple CLI entry‑point for manual testing
    asyncio.run(run_nightly())

# ---------------------------------------------------------------------------
# Public helper for the TUI to invoke a single nightly run (no sleep loop).
# ---------------------------------------------------------------------------

def run_all_once() -> None:
    """Run the nightly pipeline for all programs **once**.

    This is the entry‑point the TUI will call when the user presses the
    ``Nightly Run`` button. It loads the program registry, processes each program
    concurrently (up to a small semaphore limit), and returns when all work is
    finished. Any exceptions are logged but do not abort the whole run.
    """
    import asyncio
    from ..src.harness.programs import Registry
    from ..src.harness import store
    from ..src.harness.engine import run_recon, scan_for_vulns

    async def _run() -> None:
        registry = Registry.load(store.programs_file())
        programs = list(registry.values())
        semaphore = asyncio.Semaphore(5)
        async def _process(p):
            async with semaphore:
                try:
                    leads = await run_recon(p)
                    store.save_leads(p.name, leads)
                    vulns = await scan_for_vulns(p, leads)
                    # Save vulns using new store helpers (added later)
                    try:
                        store.save_vulns(p.name, vulns)  # type: ignore[attr-defined]
                    except AttributeError:
                        # Fallback – store.save_leads for backward compatibility
                        store.save_leads(p.name + "_vulns", vulns)
                except Exception as exc:  # noqa: BLE001
                    import logging
                    logging.getLogger(__name__).error(
                        "[nightly] error processing program %s: %s", p.name, exc
                    )
        await asyncio.gather(*[_process(p) for p in programs])

    asyncio.run(_run())

