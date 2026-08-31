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