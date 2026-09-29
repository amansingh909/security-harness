# Autopilot (experimental branch, not for normal use)

This lives on the `autopilot` branch only. It is an experiment in pushing the
harness closer to a hands-off loop. It is deliberately kept off the default
workflow. Do not merge it to main without a specific decision, and do not run it
against real programs expecting it to close bugs for you.

## The one line this keeps (even here)

The machine never sends attack traffic to a real third-party program unattended,
and it never auto-submits to a platform. Those two behaviors are what get a
HackerOne or Bugcrowd account banned and create real legal exposure, which is the
opposite of making money. On a real program, the human still runs the one manual
active test and still presses submit. That guardrail is the difference between an
aggressive research branch and an account-ending liability.

Everything short of those two, autopilot automates as far as it will go.

## What autopilot does

### Practice targets: the full loop, unattended
On `mode=practice` targets (intentionally vulnerable sites you own or are meant
to exploit: vulnweb, a local Juice Shop or DVWA), autopilot runs the whole loop
by itself: recon, active exploitation, confirm the bug, capture the
request/response evidence, and draft the report. This is the only place "prints
money on its own" is safe to realize end to end, because there is no third party
to harm. The value is a proven repro library the human replays by hand on real
leads.

### Real programs: prepare everything up to the submit
For every real-program lead in the queue, autopilot builds a complete,
ready-to-submit package so the human's job shrinks to review plus one click:

1. Derived repro steps for the specific lead (from the recon signals).
2. A candidate proof-of-concept the human runs by hand to confirm.
3. Impact analysis and a suggested severity.
4. A dedup check against public disclosures (`harness dedup`).
5. A humanized draft report, evidence fields left for the human to fill from
   what they actually observed.

The machine prepares; the human confirms and submits. This attacks the real
bottleneck to money (the per-lead human time) without the machine itself
touching a real target unattended.

## Why it is isolated

It is more aggressive and less reviewed than main. Keep it as R&D. Nothing here
flows back to main without a deliberate review, and the safe main path stays the
one you actually run.

## Status

Scaffold and design only. The engine (`harness autopilot`) is not built yet.
Build order when we do:

1. `harness autopilot --programs <practice>`: full auto loop on practice targets,
   writing proven repros into a playbook.
2. `harness autopilot --prep <real-program>`: per-lead submission-package builder
   (repro + PoC + impact + dedup + humanized draft), everything up to the submit.
3. A TUI view that opens each prepared package for the human to confirm and send.
