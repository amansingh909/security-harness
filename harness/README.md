# harness

One front door for the whole security-harness. Run it **headless** (`harness
auto` recons + scans every program and fills a review queue) or open the **TUI**
and work that queue. Either way a hunt is menu-driven instead of four tools, four
`cd`s, and a pile of env vars.

```
┌─ security-harness ───────────────────────────────┐
│ recon ✓ · cve-index ● up (12,431) · classifier ✗ · reporter ✓ │
│ Programs            │ Leads                        │
│  > acme    14 leads │ 8 dev-api…                   │
│    globex   (-)     │ 6 jenkins…                   │
│                     ├──────────────────────────────┤
│                     │ detail pane                  │
└ r recon · s search · w scaffold · e render · c classify · a add · q ┘
```

## What it does

- **Status bar**: at a glance, which components are available: recon installed?,
  cve-index up + doc count?, classifier ready?, reporter installed?
- **Programs**: define a bug-bounty program once (scope + seeds); saved to
  `~/.harness/programs.yaml` and reused. `a` to add, `d` to delete.
- **`r` Recon**: runs `recon-orchestrator` for the selected program (scope-gated,
  rate-limited) and fills the Leads table with ranked candidates.
- **Leads**: the triaged hosts, highest-priority first, with the signals that
  flagged them and any CVE matches. Select one to see detail.
- **`s` Search**: query a running `cve-index` for CVEs without leaving the app.
- **`w` Scaffold**: writes a `bounty-reporter` finding file for the highlighted
  lead, pre-filled with the facts recon knows and **TODOs for the evidence you
  must supply by hand**. It never invents repro steps or impact.
- **`e` Render**: after you fill the scaffold's TODOs, renders it to HackerOne +
  Bugcrowd JSON + Markdown. It **refuses** while any TODO placeholder remains.
- **`c` Classify**: classify a CVE/finding description (severity + CWE) via
  `cve-classifier`. Shows a clear "needs training" message until a GPU-trained
  adapter exists.

## Run it headless, review in the TUI

- **`harness auto`**: no TUI, no prompts, no upload. It recons + scans every
  program, then writes per-finding records to `~/hunts/<program>/findings/`. Safe
  to run from cron or an agent. `--programs a,b` scopes it to a subset.
- **`f` Findings**: the review queue across all programs. `r`/`f`/`x` mark a
  finding real / false / duplicate; **Enter** opens it to add the evidence you
  verified by hand, **Ctrl+D** previews the report (prose run through the
  **humanizer**, evidence left untouched), and **Ctrl+S** submits it, with a
  confirm. The submit is the one action that POSTs.
- **`harness seed-practice`**: adds the vulnweb practice program (`mode=practice`).
- **Program `mode`**: `real` programs are forced passive (GET/HEAD only);
  `practice` programs (intentionally vulnerable targets) arm the active engine.
  Set per program in `~/.harness/programs.yaml`.

Results and reports persist per program under `~/hunts/<program>/`.

> **cve-index ingest** stays a shell command (`cve-index ingest`) on purpose:
> it's a long, heavy job better run detached than from a TUI keypress. The status
> bar shows whether the service is up.

## Install

```bash
cd ~/security-harness/harness
pip install -e .
# the engine drives the sibling components; install those too:
pip install -e ../recon-orchestrator -e ../bounty-reporter
```

## Run

```bash
harness              # launch the TUI
```

Prefer commands? The same actions are available headless:

```bash
harness add acme --scope '*.acme.com' --out blog.acme.com --seed www.acme.com \
                 --cve-index-url http://localhost:8080
harness list
harness hunt acme    # run recon, print + save the ranked leads
```

## How it fits the harness

`harness` is just the control surface. The real work still lives in the
components it calls:

- recon → `recon-orchestrator` (GET/HEAD only, leads are **UNVERIFIED**; you
  confirm them by hand)
- CVE search / correlation → `cve-index`
- report scaffold → `bounty-reporter` (which refuses the file until the TODO
  evidence fields are real)

So the safety and non-fabrication guarantees of each component still hold. The
TUI just removes the typing.

## Tests

```bash
pip install -e '.[dev]' && pytest
```

Covered without a terminal: the program registry (save/load/remove), the results
store, and report scaffolding (facts filled, evidence left as TODOs). The TUI
itself is smoke-tested headless via Textual's pilot.
