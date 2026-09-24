# Resume here — Autonomous Bounty Runner (state @ 2026-09-23)

**Status:** **Milestone 1 BUILT** — 6 tasks, all committed on branch
`active-test-extension`, every suite green (harness 67, bounty-reporter 36,
recon-orchestrator 121). The harness now runs headless and findings are
reviewable/markable in the TUI. Next: practice-site exploit mode, report
drafting + humanizer, in-TUI submit.

### Milestone 1 — DONE (each its own commit, authored solely by the user)
1. `fix: launch cve-index with the venv interpreter, not poetry run` — startup crash.
2. `feat: ingest the CVE corpus once when the index is empty` — empty-DB / empty-reports.
3. `feat: per-finding record store with a mutable, review-safe status` — `findings_store.py`.
4. `feat: harness auto — headless run that fills the review queue` — non-interactive entry.
5. `feat: TUI Findings screen — review and mark the queue in place` — press `f`.
6. `fix: uploader refuses to fabricate evidence or submit unverified leads` — the landmine.

### Next up (Milestone 2)
- **Practice mode:** add a `mode: real|practice` field to `Program`; in `harness
  auto`, practice programs arm the existing active engine against practice sites,
  real programs are FORCED passive (the bright line, as a test). *Confirm the
  practice-target allow-list before arming.*
- **Report drafting + humanizer:** render a verified finding via the
  anti-fabrication path, then polish prose with the humanizer (needs an LLM
  backend — DECIDE: local ollama model vs `freeclaude`).
- **In-TUI submit:** view the full drafted report, submit with a confirm.

## Artifacts
- **Spec (approved):** `docs/superpowers/specs/2026-09-23-autonomous-bounty-runner-design.md`
- **Interface reference (verbatim signatures):** `docs/superpowers/reference/2026-09-23-interface-reference.md`
- This resume note.

## Locked decisions
- **Two modes.** `practice` = fully autonomous *including real exploitation*, only
  against intentionally-vulnerable practice sites (testphp.vulnweb.com, local
  Juice Shop / DVWA). `real` programs = passive GET/HEAD recon + auto-drafted
  candidate reports, **no autonomous attack traffic, no auto-submit** (bans + legal).
- **Human verifies + submits entirely in the TUI** (new Findings screen). Only
  command the human types is `harness` (the cockpit). Autonomous run is
  `harness auto`, fired by Hermes/cron.
- **Source of truth = `~/security-harness`** (private GitHub repo; venv points
  here so edits take effect). Symlinked into `~/Documents/GitHub/security-harness`.
  `~/pi/sand/security-harness` = Hermes deploy target (same remote, same rev).
- **NVD key** activated, validated (HTTP 200), stored in `cve-index/.env`
  (gitignored — never commit the value).

## Why the current harness "doesn't work" (fixes = Milestone 1)
1. Crashes at startup: `poetry run cve-index serve` (there's no poetry env) →
   whole run aborts. `__main__.py:482` → use the console script `cve-index serve`.
2. Empty CVE DB: nothing runs `cve-index ingest` → zero reports. Add ingest-if-empty
   (probe `GET /health`, ingest `--mode full` when `vectors == 0`).
3. Can't run headless: `harness global` launches the TUI + `getpass` + `input()`.
   Add a non-interactive `harness auto`.
4. 🚩 Its only automated path fabricates evidence and POSTs to real programs
   (`bounty_reporter/uploader.py:36-114`). Neuter it.

## Milestone 1 = "runs headless + findings viewable in the TUI"
1. Service start fix (poetry → console script).
2. Ingest-if-empty step.
3. `harness auto` non-interactive command (no TUI/getpass/input) → recon + scan
   (real mode) → persist finding records. (Register in `__main__.py` near line 713;
   add `_cmd_auto` to the hardcoded list in `test_cli.py:94`.)
4. New **finding store**: per-finding record with a mutable `status`
   (ready / needs-check / real / false) under `~/hunts/<program>/findings/*.json`.
   Today only a `vulns.json` blob exists — no per-finding status (confirmed).
5. New TUI **FindingsScreen** (parallel to `TriageScreen`, app.py:236-298) reading
   the store: browse / view / mark.
6. Safety: neuter the fabricating uploader.

**Deferred to plan 2:** humanizer prose (needs an LLM backend — no LLM client in
repo today; decide Hermes/ollama vs freeclaude), practice/active exploit mode,
in-TUI submit, CVSS field-mismatch fix, ScopeGuard re-check on `scan_for_vulns`.

## Open questions for next time
- Confirm command name `harness auto` (assumed).
- Practice-target defaults (vulnweb + local Juice Shop/DVWA) — settle at plan 2.
- Humanizer LLM backend choice — plan 2.
