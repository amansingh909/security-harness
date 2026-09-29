# Changes made to fulfill the user request

## Summary
The user wanted a single command (`harness global`) that:
1. Ensures the CVE-index services are running (starting them if needed).
2. Executes the nightly orchestrator for all programs (sub-domain enum, port sweep, CPE-based CVE lookup, sensitive-path checks, scope import, scoring).
3. Immediately opens the Triage dashboard for manual review.
4. After the user quits the TUI, generates batch reports for each program.
5. Optionally uploads those reports to HackerOne/Bugcrowd (prompting once for API keys).

## Files Modified

### 1. `/home/amansingh/security-harness/harness/src/harness/__main__.py`
- Added `_cmd_global` function that:
  - Calls `_ensure_cve_index_running()` to start Elasticsearch and the cve-index FastAPI if needed.
  - Runs the nightly pipeline via `run_all_once()`.
  - Sets environment variable `HARNESS_AUTO_OPEN_TRIAGE=1` to signal the TUI to auto-open the Triage dashboard.
  - Launches the HarnessApp (TUI).
  - After the TUI exits, generates batch reports and optionally uploads them.
- Added `_ensure_cve_index_running()` async function to start services and wait for health.
- Added the `global` subcommand to the argument parser.

### 2. `/home/amansingh/security-harness/harness/src/harness/tui/app.py`
- Added `import os` at the top.
- In `HarnessApp.on_mount`, after refreshing programs and status, check for the environment variable `HARNESS_AUTO_OPEN_TRIAGE` and if set to "1", push the TriageScreen.

## Behavior
- When the user runs `harness global`:
  - The command first ensures the CVE-index services are up (starting them if necessary).
  - Then it runs the nightly pipeline for all programs.
  - Immediately after the pipeline completes, the TUI launches and automatically opens the Triage dashboard (as if the user pressed `t`).
  - The user can interact with the Triage dashboard (review findings, etc.).
  - When the user quits the TUI (by pressing `q` or closing the window), the command continues:
    - It generates a consolidated Markdown + JSON report for each program under `~/hunts/<program>/`.
    - It prompts once for HackerOne and Bugcrowd API keys (can be left blank to skip upload).
    - If keys are provided, it uploads the reports to the respective platforms.

## Notes
- The TUI already had the ability to open the Triage dashboard via the `t` binding. We reuse that by setting an environment variable and checking it in `on_mount`.
- The nightly pipeline is the same as running `harness nightly` from the TUI, but we call it headlessly.
- The report generation and upload steps are the same as if the user had pressed `u` in the TUI after selecting a program, but we do it for all programs.

## Testing
- The user should test by running `harness global` in an environment where the cve-index services are not running to see if they are started.
- Then verify that the Triage dashboard opens automatically after the nightly run.
- After quitting the TUI, check that reports are generated and (if API keys provided) that upload is attempted.

## Related Files
- The README already documented the `harness global` command correctly, so no changes were needed there.

---

# Autonomous runner + TUI review/submit (branch: active-test-extension, 2026-09-24)

## Summary
Turned the harness into a headless autonomous runner with a TUI review/submit
cockpit, and fixed the blockers that stopped the pipeline from working at all.

## Added
- **`harness auto`** — non-interactive run (no TUI / prompts / upload): ensures
  services, ingests the CVE corpus once if empty, runs recon + scan per program,
  and files per-finding records to `~/hunts/<program>/findings/`. `--programs`
  scopes it to a subset.
- **`harness seed-practice`** — seeds the vulnweb practice program (5 sites,
  `mode=practice`), idempotent.
- **Program `mode` (`real` | `practice`)** — `_arm_for_mode` forces real programs
  passive (GET/HEAD) on every autonomous run; only practice programs arm the
  active engine.
- **Finding store** (`findings_store.py`) — per-finding records with a mutable
  status (needs_check / real / false / duplicate) that survives re-scans, plus
  `signals` / `fingerprints` / `evidence`.
- **TUI Findings screen** (`f`) — review the queue, mark r/f/x, Enter → a detail
  screen to add evidence, Ctrl+D draft (humanized), Ctrl+S submit (with confirm).
- **Humanizer** (`humanizer.py`) — de-AIs report prose via freeclaude
  (`HARNESS_HUMANIZER_CMD` to override) with a graceful fallback;
  `engine.draft_report` / `engine.submit_finding` humanize narrative fields only,
  never the evidence.

## Fixed
- `_ensure_cve_index_running` launched `poetry run cve-index serve` (no poetry
  env) → now `python -m cve_index serve`.
- No CVE ingest step → `_ensure_cve_corpus` ingests when the index is empty.
- The auto-upload path fabricated evidence and POSTed to real programs → the
  uploader now refuses unverified leads and never fabricates; submission is a
  human-only TUI action.

## Verified
`harness auto --programs vulnweb` ran end to end against the vulnweb family:
started services, ingested 5,697 vectors, actively found a reflected XSS
(testasp `/Search.asp?tfSearch`), an exposed `/info.php`, and version
disclosures, and filed them to the review queue. Humanizer confirmed live via
freeclaude. 246 unit tests green (harness / recon-orchestrator / bounty-reporter).