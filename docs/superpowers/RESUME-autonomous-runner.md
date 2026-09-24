# Resume here — Autonomous Bounty Runner (state @ 2026-09-23)

**Status:** **Milestones 1-2 built and LIVE-VERIFIED against vulnweb** (2026-09-23).
All committed on branch `active-test-extension`, suites green (harness 83,
bounty-reporter 36, recon-orchestrator 121). Next: in-TUI submit flow.

### Live verification (2026-09-23)
`harness auto --programs vulnweb` ran the whole pipeline end to end: started
services, ingested the CVE corpus (5,697 vectors, semantic search live), ran
active recon against the vulnweb family, filed findings, and tore services down.
The active engine found real bugs — **reflected XSS** on testasp.vulnweb.com
(`/Search.asp` via `tfSearch`), **exposed `/info.php`** on rest.vulnweb.com, and
version disclosures — all `needs_check` in the review queue. **Bug found and
fixed during the run:** the queue was built from the (empty) CVE-correlation
pass; it now builds from the recon leads, where the signals actually live
(`record_from_lead` + `url`/`signals`/`fingerprints` on `FindingRecord`).

### Milestone 1 — DONE (each its own commit, authored solely by the user)
1. `fix: launch cve-index with the venv interpreter, not poetry run` — startup crash.
2. `feat: ingest the CVE corpus once when the index is empty` — empty-DB / empty-reports.
3. `feat: per-finding record store with a mutable, review-safe status` — `findings_store.py`.
4. `feat: harness auto — headless run that fills the review queue` — non-interactive entry.
5. `feat: TUI Findings screen — review and mark the queue in place` — press `f`.
6. `fix: uploader refuses to fabricate evidence or submit unverified leads` — the landmine.

### Milestone 2 — mostly DONE
- ✅ **Practice/real mode:** `Program.mode` + `_arm_for_mode`; `harness auto`
  FORCES real programs passive and arms practice programs (bright line, tested).
- ✅ **Humanizer:** `harness/humanizer.py` via **freeclaude** (override with
  `HARNESS_HUMANIZER_CMD`); returns text unchanged if the model is down.
- ✅ **Report drafting:** `engine.draft_report(finding)` renders a verified
  finding and humanizes ONLY summary/impact/remediation, never the evidence.
- ✅ **Practice targets seeded:** `harness seed-practice` adds the vulnweb family
  (testphp/testasp/testaspnet/testhtml5/rest.vulnweb.com) as one `mode=practice`
  program — already run into `~/.harness/programs.yaml`.

### Still to do
- **In-TUI submit flow:** open a finding → view its drafted (humanized) report →
  submit with a confirm (the only thing that POSTs). Real-program leads need an
  evidence-entry step first; practice findings carry active-engine evidence.
  Building blocks are in place: `engine.draft_report` + the neutered uploader.
- **Hermes/sandbox deploy:** `git pull` into `~/pi/sand`, schedule `harness auto`.

### Note for whoever runs `harness auto`
The user has real programs in `~/.harness/programs.yaml` (`trazo`, a Vercel
preview). Auto sweeps them too, but `_arm_for_mode` forces every real-mode
program **passive** (GET/HEAD) — only `vulnweb` (practice) is actively tested.
An owned asset the user wants auto to actively test must be set `mode=practice`.

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
