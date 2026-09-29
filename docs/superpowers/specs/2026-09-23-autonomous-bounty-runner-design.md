# Autonomous bug-bounty runner: design spec

**Date:** 2026-09-23
**Status:** Draft for review
**Repo:** `~/security-harness` (canonical; private). Sandbox clone at `~/pi/sand/security-harness` is the Hermes deployment target.

## 1. Intent

Turn the existing `security-harness` into something that runs **unattended** and
leaves the operator a stack of **review-ready draft reports** each time it runs.
The machine does all the tedious work; the human does only two things:

1. Decide which drafted findings are real (and run the one manual check where needed).
2. Submit.

**Both happen inside the TUI.** The operator launches one screen and reviews,
marks, and submits from there, with no hand-editing files and no `submit`
command. The only shell invocation is the headless autonomous run, and
Hermes/cron fires that; the operator doesn't type it. ("i dont wanna have to use
many commands.")

This is the operator's stated goal: "just need it to be autonomous so I can do
other things," with "all the human-needed stuff like reviewing and submitting"
kept manual.

## 2. Bright lines (non-negotiable, enforced in code + tests)

These exist because crossing them means a platform ban (→ $0) or legal exposure,
which defeats the whole point.

- **No autonomous attack traffic against real in-scope programs.** Real-mode
  recon is GET/HEAD only. Payload injection / active exploitation is *impossible*
  in real mode, not just off-by-default.
- **No auto-submission, ever.** Nothing in the autonomous path POSTs to a
  platform. Submission is a separate, explicit, human-only command.
- **No fabricated evidence.** Reports are built only from captured, real evidence
  (request/response, observed result). The report builder refuses boilerplate.
- **Humanizer polishes prose only** (summary / impact / remediation wording).
  It never touches evidence fields (repro steps, request/response, CVSS) and
  never invents content.

## 3. Two modes (per-program `mode` field)

Set once per program in `~/.harness/programs.yaml`.

### `practice`: fully autonomous, real exploitation
- Targets: intentionally vulnerable sites that exist to be exploited
  (`testphp.vulnweb.com`; locally-run OWASP Juice Shop / DVWA via docker;
  operator-owned lab hosts). Configurable allow-list per practice program.
- Arms the **existing** active engine (`_run_active_tests` → crawl → param
  discovery → payload injection; optional OWASP ZAP driver).
- Full loop: exploit → confirm → capture request/response evidence → auto-render
  a report. Output is proof the engine works + a repro library the operator can
  replay by hand on real targets.
- Still scope-gated; practice targets are explicitly whitelisted.

### `real`: passive recon + candidate drafts, no attack traffic
- `active_tests` forced `False` (enforced, not default).
- GET/HEAD recon + non-intrusive confirmation only.
- Observation-confirmable findings → auto-drafted candidate reports.
- Everything needing a payload → queued as a lead **with** a ready-to-run repro,
  for the human to confirm. Never auto-reported, never submitted.

## 4. Finding routing in real mode

**Auto-draft (confirmed by GET-only observation):**
- Exposed `.git` / `.env` / backup files, directory listing
- CORS `*` + credentials
- Missing/weak security headers (drafted at appropriate low severity)
- Version-disclosed service matching a known CVE (via `cve-index`)
- Secrets in JS bundles
- Subdomain-takeover fingerprints

**Queue for human (needs an active payload):**
- SQLi, XSS, IDOR, SSRF, auth bypass, RCE, etc. → lead + suggested repro.

## 5. The headless runner (lean approach)

New non-interactive command (working name `harness auto`, `--programs a,b`
optional). Reuses the existing engine→component glue. Steps:

1. **ensure_services**: start ES (docker) + `cve-index` via the **console
   script** (`cve-index serve`) / `python -m`, *not* `poetry run`. Adopt an
   already-running instance on :8080.
2. **ensure_corpus**: run `cve-index ingest` if the index is empty/stale
   (bounded by `CVE_NVD_MAX_RECORDS`; incremental afterward). Uses the NVD key
   now in `cve-index/.env`.
3. **per program**: recon (mode-appropriate) → `scan_for_vulns` (now with a
   ScopeGuard re-check + rate limiting; see §7).
4. **persist findings**: route through the *legit* anti-fabrication render path
   (`bounty-reporter`) → humanizer prose pass → save each as a **finding record**
   (structured `.json` + rendered `.md`) under `~/hunts/<program>/findings/`,
   tagged `status: ready` (observation-confirmed) or `status: needs-check`
   (queued lead, with suggested repro attached). This store is what the TUI reads.
5. **the store is the queue**: no separate index file. The TUI's Findings screen
   lists everything across programs straight from the store (§6).
6. **No** `getpass`, `input()`, TUI, or upload anywhere in this path.

## 6. Review and submit in the TUI (not commands)

The operator does everything from one screen. Launching the TUI (`harness`, no
args) opens a **Findings** screen that reads the store from §5:

- **Browse** every drafted finding across all programs, filterable by status
  (`ready` / `needs-check`) and program.
- **View** the full rendered report inline: evidence, repro, CVSS, humanized prose.
- **Mark** a finding real / false / duplicate (persists back to the record, so a
  finding is only ever reviewed once).
- For `needs-check` leads: the suggested repro is shown inline so the operator
  runs the one manual test, then flips it to real.
- **Submit** a finding marked real with a single keypress → renders via the
  anti-fabrication path (refuses unfilled/boilerplate evidence), shows a final
  confirm dialog, then uploads to the program. This is the **only** action that
  POSTs, it is always human-triggered, and it is never reachable from the
  autonomous path.
- AI-assistance disclosure toggle applied here if the program requires it.

No `submit` shell command, no hand-editing YAML. The autonomous runner fills the
store; the operator works the store in the TUI.

## 7. Fixes to existing defects (from diagnosis, most-blocking first)

1. **Service start**: replace `poetry run cve-index serve` with the console
   script (Blocker A: currently aborts the whole run on step 0).
2. **Ingest step**: add it; without it the CVE base is empty → zero reports
   (Blocker B).
3. **Interactivity**: headless path bypasses TUI/`getpass`/`input`.
4. **Fabricating uploader**: remove `uploader._build_finding`'s invented
   evidence from any automated path; upload only through the manual §6 command,
   which uses filled, human-verified findings.
5. **`scan_for_vulns` re-probe**: add ScopeGuard re-check + rate limiter (it
   currently re-probes hosts on its own client, bypassing both).
6. **CVSS field mismatch**: map `cvss_severity`/`cvss_score`/`why` correctly so
   vectors/exploit flags stop rendering as N/A.
7. **(later)** Package or delete the orphaned `nightly`/`triage` dirs; optionally
   salvage the HTML dashboard as a read-only web view.

## 8. Humanizer integration

After render, pass only the narrative sections (summary, impact, remediation)
through the `humanizer` skill. Leave repro steps, request/response, and CVSS
untouched. Never invent, which aligns with the operator's never-hallucinate rule
and the report builder's existing anti-fabrication validators.

## 9. Scheduling / Hermes (final phase)

1. Sync canonical → `~/pi/sand` (git pull; same remote/rev today).
2. Stand up the sandbox venv (the sandbox clone's venv currently points at the
   mirror; fix so it's self-consistent inside the jail).
3. Hermes / cron invokes `harness auto` (headless).
4. Runs deposit findings in the store; the operator reviews/submits in the TUI on
   their own schedule.

## 10. Testing

- **Unit:** real mode never arms `active_tests`; `scan_for_vulns` honors scope +
  rate limit; uploader refuses boilerplate; humanizer leaves evidence fields
  byte-identical; headless path contains no interactive calls; the TUI submit
  action goes through the anti-fabrication path + explicit confirm and is not
  wired to any autonomous entry point; marking a finding persists to its record.
- **Integration:** end-to-end headless run against a local Juice Shop produces a
  report; real-mode dry run against an owned test domain produces candidate
  drafts and emits **only** GET/HEAD (assert on captured traffic).

## 11. Rollout order

1. Source-of-truth + service-start + ingest → `harness run --headless` produces
   *something* end-to-end (real mode, one program).
2. Finding store + drafting via anti-fabrication path + humanizer + **TUI
   Findings screen** (browse, view, mark real/false).
3. Practice mode (arm active engine, practice targets, evidence capture).
4. Remove fabricating uploader + **in-TUI submit** (human-triggered, confirm).
5. Hardening: scope re-check, CVSS field fix, tests.
6. Hermes/sandbox deployment + scheduling.

## Open defaults (operator can adjust on review)

- **Practice targets:** ship with `testphp.vulnweb.com` + support for local
  Juice Shop/DVWA. Add PortSwigger Academy? (needs a session token, deferred.)
- **Commands (kept minimal):** operator uses `harness` (no args) → TUI cockpit.
  Autonomous run (Hermes/cron only) = `harness auto` (headless). The operator
  types at most one command; everything else is in the TUI.
- **Run cadence once on Hermes:** nightly? on-demand?
