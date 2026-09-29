# bounty-reporter

Turn a **structured, validated finding** into triage-ready reports:
HackerOne and Bugcrowd submission JSON plus a Markdown write-up, with a
**spec-accurate CVSS v3.1** score computed from the vector (not trusted from
whatever number was typed in).

Report structure follows the triage best-practice order: Title, Summary,
Steps to Reproduce, Proof of Concept, Impact, Severity, Classification,
Remediation.

## Non-fabrication by design

A report is only as good as its evidence. The `Finding` model **requires** a
vulnerability type, an affected asset, reproduction steps, an observed result,
and an impact statement. If any are missing it refuses to build the report and
tells you exactly what's missing. It never invents repro steps, impact, or a
severity. Severity is only asserted when you supply a CVSS vector (then it's
computed); otherwise the report says "unrated, argue from impact."

This is the same discipline that keeps CVE hallucinations out: the optional
enrichment step verifies any `CVE-YYYY-NNNN` mentioned in the finding against a
running `cve-index` rather than trusting recall.

## Use

```bash
pip install -e .

# Render the bundled worked example (IDOR) to stdout:
bounty-reporter render examples/idor.yaml --format markdown

# Write all three artifacts to a directory (named by dedup fingerprint):
bounty-reporter render examples/idor.yaml --out ./out
#   -> out/<fp>.md  out/<fp>.hackerone.json  out/<fp>.bugcrowd.json
```

A finding file (`.yaml` or `.json`) looks like `examples/idor.yaml`. The same
dict shape is what an upstream analysis step (e.g. the classifier or an LLM
triage pass) would emit. `Finding.from_dict()` validates it before anything is
rendered.

## What you get

- **CVSS v3.1**: `bounty_reporter.cvss.base_score()` implements the FIRST
  equations including the exact roundup; verified against Log4Shell (10.0),
  `AV:N…C:H` (7.5), the IDOR vector (6.5), and null-impact (0.0).
- **Program-native taxonomy**: CWE to HackerOne weakness name and Bugcrowd VRT
  id, because not every program uses CVSS.
- **Dedup fingerprint**: `program + vuln_type + host + path + param`, so
  `?id=1` and `?id=2` collapse to one bug; `dedupe()` filters a batch.

## Tests

```bash
pip install -e '.[dev]' && pytest
```

Everything above is unit-tested (CVSS reference vectors, model validation,
dedup, taxonomy mapping, end-to-end generation) with no external services.
Enrichment (`bounty_reporter.enrich`) needs `pip install -e '.[enrich]'` and a
running `cve-index`.
