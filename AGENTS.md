# Autonomous operator playbook

For any agent (Hermes, a cron job, or a human) driving this harness. Follow it
top to bottom. It tells you how to read a program's requirements, configure the
harness to meet them, run it, and triage — without breaking a program's rules.

---

## 0. Golden rules — never violate these

1. **Real programs are passive only.** A real bug-bounty program runs GET/HEAD
   recon. Never arm active testing (`mode=practice`) on a real program. Active
   exploitation is for **practice** targets only (intentionally-vulnerable sites).
2. **Never submit.** You fill the review queue. A **human** verifies each finding,
   adds evidence, and submits from the TUI. You do not POST to any platform.
3. **Never fabricate evidence.** Report only what was actually observed.
4. **Only touch in-scope assets.** Respect the imported in/out scope. Never probe
   an out-of-scope host or a non-host asset (mobile app, physical device, etc.).
5. **A required testing header MUST be set before any run.** If a program requires
   a header (e.g. CLEAR's `X-Bug-Bounty`) and it is not set, **do not run** — a
   header-less request can forfeit the reward.
6. **If a program prohibits automated scanning, do not run recon.** Flag it for
   the human and stop. Asset-in-scope does not mean automation-allowed.

If any rule can't be satisfied, **stop and leave a note for the human.** Doing
nothing is always safe; guessing is not.

---

## 1. Onboard a new program

### Step 1 — Read the requirements
```
harness show-policy <handle>
```
Read the policy and extract, explicitly:

- **Required testing header(s)?** e.g. `X-Bug-Bounty: HackerOne-<username>`. Note
  the exact name and the exact value format.
- **Is automated scanning allowed?** Look for "no automated scanning", "no
  scanners", rate-limit rules, "do not brute force". If automation is
  **prohibited → STOP**, flag the human. If only aggressive scanning is barred,
  passive rate-limited recon is fine.
- **Special testing instructions?** pre-testing URLs, lead-source links, test
  accounts. Note them for the human (some can't be automated).
- **Prohibited actions:** social engineering, DoS, mass account creation,
  accessing real user data — the harness won't do these, but confirm nothing in
  your plan does.

### Step 2 — Import scope
```
harness import-scope <handle>
```
This pulls the structured in/out scope from HackerOne, creates the program as
**real (passive)**, tags it so `harness auto` re-pulls fresh scope each run, and
**skips non-host assets** (apps, APIs, path-scoped URLs) for the human to review.

### Step 3 — Set required headers
For each required header from Step 1:
```
harness set-header <handle> <Header-Name> <Header-Value>
# example:
harness set-header clear X-Bug-Bounty HackerOne-<your-username>
```
The header then rides **every** request the harness makes to that program.

### Step 4 — Go / no-go gate
Confirm all of these before running. If any is "no", **STOP**:
- [ ] Every required header is set (Step 3)?
- [ ] Automated (passive) recon is allowed by the policy (Step 1)?
- [ ] Scope imported and it's `mode=real` (passive)?

---

## 2. Run
```
harness auto --programs <handle>      # one program
harness auto                          # every program you've onboarded
```
`auto` is non-interactive (no prompts, no upload). It refreshes scope from the
API, carries the program's headers on every request, runs **passive** recon
(GET/HEAD, rate-limited, scope-gated), and files findings to the review queue.

---

## 3. What to look for (triage priorities)

The queue is a worklist. Rank leads like this — highest first:

- **Auth boundaries (401/403)** on sensitive endpoints → worth manual
  access-control / IDOR testing.
- **Exposed secrets** — `.git`, `.env`, backups, secrets in JS bundles.
- **CORS `*` with credentials**, **subdomain takeover** fingerprints.
- **Version-disclosed services with a known CVE** (the CVE pass surfaces these).
- Map each to the program's **qualifying vulnerabilities** (XSS, IDOR, SSRF, auth
  bypass, RCE, SQLi…). A lead that matches a qualifying class is worth more.
- **Lowest:** missing security headers alone — rarely paid unless chained. Don't
  waste the human's time leading with these.

The interesting leads need **manual active testing** to confirm on a real
program — that is the human's job. **You do not exploit real programs.** Leave the
lead + its signals in the queue; the human takes it from there.

---

## 4. Hand off to the human

Findings sit in `~/hunts/<program>/findings/`. The human opens the TUI:
```
harness    # then press f
```
Reviews the queue, opens a lead (Enter), adds the evidence they verified by hand,
previews the humanized report (Ctrl+D), and submits (Ctrl+S). **Only the human
submits.**

---

## 5. Practice mode (safe autonomous exploitation)

To develop and validate exploit techniques with no third party to harm:
```
harness seed-practice                 # adds the vulnweb practice program
harness auto --programs vulnweb       # full active exploitation, safe
```
Practice programs (`mode=practice`) are the **only** place active exploitation
runs autonomously. Techniques proven here become the human's repro playbook for
verifying real-program leads by hand.

---

## Worked example — CLEAR (a program that requires a header)

```
harness show-policy clear                          # -> requires X-Bug-Bounty header
harness import-scope clear                         # 13 in-scope, 4 out, apps skipped
harness set-header clear X-Bug-Bounty HackerOne-<your-username>
harness auto --programs clear                      # passive, header on every request
harness                                            # press f -> review the queue
```
CLEAR's passive run surfaces auth boundaries (403) on `concierge` / `scan` /
`authentication.clearme.com` — those are where the human spends manual testing.
