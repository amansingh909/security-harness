# harness

One TUI that drives the whole security-harness, so a hunt is menu-driven instead
of four tools, four `cd`s, and a pile of env vars.

```
┌─ security-harness ──────────────┐
│ Programs            │ Leads       │
│  > acme    14 leads │ 8 dev-api…  │
│    globex   (-)     │ 6 jenkins…  │
│                     │ …           │
│                     ├─────────────┤
│                     │ detail pane │
└ r recon · s search · w report · a add · q quit ┘
```

## What it does

- **Programs** — define a bug-bounty program once (scope + seeds); it's saved to
  `~/.harness/programs.yaml` and reused. `a` to add, `d` to delete.
- **`r` Recon** — runs `recon-orchestrator` for the selected program (scope-gated,
  rate-limited) and fills the Leads table with ranked candidates.
- **Leads** — the triaged hosts, highest-priority first, with the signals that
  flagged them and any CVE matches. Select one to see detail.
- **`s` Search** — query a running `cve-index` for CVEs without leaving the app.
- **`w` Report** — scaffolds a `bounty-reporter` finding file for the highlighted
  lead, pre-filled with the facts recon knows and **TODOs for the evidence you
  must supply by hand**. It never invents repro steps or impact.

Results persist per program under `~/hunts/<program>/`.

## Install

```bash
cd ~/security-harness/harness
pip install -e .
# the engine drives the sibling components — install those too:
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

`harness` is just the control surface — the real work still lives in the
components it calls:

- recon → `recon-orchestrator` (GET/HEAD only, leads are **UNVERIFIED**; you
  confirm them by hand)
- CVE search / correlation → `cve-index`
- report scaffold → `bounty-reporter` (which refuses the file until the TODO
  evidence fields are real)

So the safety and non-fabrication guarantees of each component still hold — the
TUI just removes the typing.

## Tests

```bash
pip install -e '.[dev]' && pytest
```

Covered without a terminal: the program registry (save/load/remove), the results
store, and report scaffolding (facts filled, evidence left as TODOs). The TUI
itself is smoke-tested headless via Textual's pilot.
