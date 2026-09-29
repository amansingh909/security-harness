# security-harness interface reference (verbatim, snapshot 2026-09-23)

> Extracted for the Autonomous Bounty Runner plan so we don't re-explore. Line
> numbers are a 2026-09-23 snapshot and will drift as code changes. Canonical
> tree: `/home/amansingh/security-harness/`. **No `conftest.py` exists anywhere**
> (outside venvs); fixtures are inline / `tmp_path` + `monkeypatch` only.

## 1. Harness front door: `harness/src/harness/__main__.py`

### 1a. Subcommand registration (`main()`, 674-746)
No-arg parsers use `.set_defaults(func=...)`; dispatch is `args.func(args)`; no
command → `_cmd_tui`.
```python
711:    p_global = sub.add_parser("global", help="run nightly pipeline ...")
713:    p_global.set_defaults(func=_cmd_global)
716:    p_scope = sub.add_parser("import-scope", help="...")
720:    p_scope.add_argument("handle", ...)
725:    p_scope.set_defaults(func=_cmd_import_scope)
742:    args = parser.parse_args()
743:    if not getattr(args, "command", None):
744:        _cmd_tui(args)
745:    else:
746:        args.func(args)
```
**Add `auto`:** near 713 → `p_auto = sub.add_parser("auto", ...); p_auto.set_defaults(func=_cmd_auto)`; define `def _cmd_auto(args): ...`. **`test_cli.py:94` (`test_every_subcommand_handler_exists`) hardcodes the handler-name list, so add `_cmd_auto` there.**

### 1b. `_ensure_cve_index_running` (444-512): the poetry bug
Starts ES via `docker compose up -d elasticsearch` (467, cwd=`_cve_index_dir()`),
then the server with **`["poetry", "run", "cve-index", "serve"]` (line 481-482)**,
which is the crash (no poetry env). Writes pid to `~/.cve_index_pid` (487-489).
Waits on health (30s). Adopts an already-serving instance (458-459).
Health helper: `_cve_index_healthy(url="http://localhost:8080")` (435-442) wraps
`engine.cve_index_health(url).get("up")`. **Fix: `["cve-index","serve"]` (console
script on PATH) or `[sys.executable,"-m","cve_index","serve"]`.**

### 1c. `_run_pipeline` (515-542)
```python
528:            leads = await engine.run_recon(program)
529:            store.save_leads(prog_name, leads)
537:            vulns = await engine.scan_for_vulns(program, leads)
538:            store.save_vulns(prog_name, vulns)
```

### 1d. `_cmd_global` (544-634): interactivity to bypass in `harness auto`
- `asyncio.run(_ensure_cve_index_running())` (558); aborts on failure (559-565).
- `Registry.load(programs_file())`, `_run_pipeline` (572-577).
- **`os.environ["HARNESS_AUTO_OPEN_TRIAGE"]="1"; HarnessApp().run()` (580-582)**, the TUI.
- **`getpass(...)` for H1/BC keys (589-590)**; per-program **`input(... [y/N])` (612)**.
- `engine.render_batch_report(prog_name, vulns, out_dir)` (599); `upload_report(...)` (625).
Module state (230-231): `_cve_index_server_proc=None`, `_we_started_cve_stack=False`.

### 1e. `_load_env_file` (412-432)
Reads `config_dir()/.env`, `os.environ.setdefault(key, value)` (real env wins).
Called first in `main()` (675). Other secrets read via `os.getenv`: `H1_API_KEY`,
`H1_IDENTIFIER`, `BC_API_KEY`, `ZAP_API_URL`, `ZAP_API_KEY`, `VERCEL_*`.

## 2. Engine: `harness/src/harness/engine.py`
`ComponentMissing(RuntimeError)` (15-16). **Engine is a MODULE OF FREE FUNCTIONS,
no `Engine` class.** Lazy imports inside each fn.
```python
19:async def run_recon(program: Program) -> list[dict]
67:async def search_cve(query, cve_index_url, k=10) -> list[dict]
77:def render_report(finding_path: str) -> dict         # {"out_dir","fingerprint","rating","cvss"}
125:def available() -> dict[str,bool]                    # {"recon","reporter","classifier"}
143:async def cve_index_health(url) -> dict             # {"up": bool, "vectors": int|None}
157:async def scan_for_vulns(program, leads) -> list[dict]
398:def classify(description) -> dict                    # {"severity","cwe","raw"} (torch)
416:def render_batch_report(program_name, vulns, out_dir: Path) -> Path
```
### 2a. Vuln dict shape (`scan_for_vulns`)
```python
# per-CVE (269-278): key is `id` NOT cve_id
{"id","product","version","cvss_severity","cvss_score","why","source":"cve-index"}
# per finding (281-286):
{"host","service": {host,port,scheme,server,powered_by,status_code[,title]},
 "cves":[...], "priority_score": int}
```
Ports probed: `[80,443,8080,8443,9999]` (326).
**Field mismatch:** real vulns have NO `cvss_vector` / `exploit_available`, but
`render_batch_report` (521-527), TUI Triage (`exploit_available`, app.py:278) and
`uploader._build_finding` (`cvss_vector`) read them → always defaults in prod.
Source models: `CveCandidate` (recon_orchestrator/models.py:20:
`cve_id,product,version,cvss_severity?,cvss_score?,why`); `Fingerprint`
(`product,version?,evidence`). `render_batch_report` writes `{prog}_report.json`
+ `{prog}_report.md` to `out_dir`, returns the `.md`.

## 3. Programs and storage
### `Program`: `programs.py:12-33`
```python
name: str
in_scope / out_of_scope / seeds: list[str] = []
seeds_file: str|None; cve_index_url: str|None; requests_per_second: float = 2.0
allow_multilevel_wildcard: bool = True
active_tests: bool = False        # <- the exploit gate
use_zap: bool = False
notes: str = ""
def is_runnable(self) -> tuple[bool,str]   # needs in_scope + (seeds or seeds_file)
```
**NO `mode` field yet**; add one. `Registry.load/save` round-trips via `model_dump()`.
`Registry` (36-74): `load(path)->Registry`, `save(path)`, `add`, `get(name)->Program|None`,
`remove`, `names()->list[str]` (sorted). YAML `{"programs": {name:{...}}}`.

### Paths: `paths.py` (whole file)
```python
config_dir() -> Path   # $HARNESS_HOME or ~/.harness
hunts_dir()  -> Path   # $HARNESS_HUNTS or ~/hunts
programs_file() -> config_dir()/programs.yaml
ensure_dirs()          # mkdir config + hunts
```
### Findings persistence: `store.py`
Per-program dir `hunts_dir()/<sanitized>`. `save_leads/load_leads` (`leads.json`),
`save_vulns/load_vulns` (`vulns.json`), `last_run(name)`. **NO per-finding record
with a mutable status anywhere, confirmed.** vulns are opaque list-of-dict blobs,
whole file rewritten each scan. (Milestone 1 introduces the status'd store.)

## 4. TUI: `harness/src/harness/tui/app.py`
Textual **8.2.8**; `CSS_PATH="app.tcss"`. `class HarnessApp(App[None])` (301).
Screens are `ModalScreen` subclasses pushed via `self.push_screen(Screen(...), cb)`
(no SCREENS dict). BINDINGS (307-324): `r`recon `v`scan `t`triage `u`upload `a`add
`?`help `q`quit; hidden: `i z n s w e c d`. Ctor (326-331): `ensure_dirs();
self.registry=Registry.load(programs_file()); current_program/leads`. Workers use
`@work(exclusive=True)` / `@work(thread=True,...)`.
Auto-open (359-360): `if os.environ.pop("HARNESS_AUTO_OPEN_TRIAGE",None)=="1":
self.call_after_refresh(lambda: self.push_screen(TriageScreen(self.registry)))`.

### `TriageScreen` (236-298): template for `FindingsScreen`
```python
class TriageScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape","cancel","Close"), Binding("q","cancel","Close")]
    def __init__(self, registry): super().__init__(); self.registry = registry
    def compose(self): yield Header(show_clock=True); yield DataTable(id="triage-table", cursor_type="row"); yield Footer()
    def on_mount(self):
        t = self.query_one("#triage-table", DataTable)
        t.add_columns("Program","Score","Host:Port","Service","CVE Count","Exploit","Sensitive")
        self._populate_table()
    def _populate_table(self):        # reads store.load_vulns(prog) per registry.names(), sorts by priority_score, top 20, add_row(... key=f"{prog}_{hostport}")
    def action_cancel(self): self.dismiss(None)
```
Score coloring: module helper `_score_cell(score)->rich.text.Text` (34-52). Row
selection app-wide: `HarnessApp.on_data_table_row_selected` (app.py:434) keyed by
`event.data_table.id`. Push pattern: `action_triage` (609-614) guards empty
registry then `self.push_screen(TriageScreen(self.registry))`.

## 5. bounty-reporter
### `Finding`: `models.py:13-86`
Required (non-blank validated): `program, vuln_type, asset, steps_to_reproduce
(min_length=1, non-blank), observed_result, impact`. Optional: `summary, title,
affected_param, poc_request, poc_response, cvss_vector, cwe (must match CWE-\d+),
remediation, references[], attachments[]`. `from_dict(data)` wraps ValidationError
→ friendly "missing evidence" ValueError. `resolved_title()`.
### `generate(finding: Finding) -> GeneratedReport`: `generator.py:26-51`
`GeneratedReport(fingerprint, cvss_score, rating, cwe, markdown, hackerone: dict,
bugcrowd: dict)`. CVSS from `finding.cvss_vector` (default rating "UNRATED").
### TODO refusal: **`harness/src/harness/findings.py` `unfilled_todos` (62-75)**
`_REQUIRED=("vuln_type","asset","observed_result","impact")`; flags fields whose
value starts "TODO", plus all-TODO steps. Enforced in `engine.render_report`
(100-105) → `ValueError("still has TODO placeholders in: ...")`.
### `uploader.py`: NEUTER THIS
`_build_finding(program, vuln) -> Finding` (36-114) **fabricates** required evidence
from scan output: `vuln_type` from cve id (76-79), boilerplate `steps` (84-93),
`observed` from banner (94-96), and `impact = "Potential security issue affecting
the asset."` (98). `upload_report(report_path, program, h1_api_key, bc_api_key,
h1_identifier=None)` (128) reads JSON `vulnerabilities`, POSTs H1
`https://api.hackerone.com/v1/reports` (Basic auth) + Bugcrowd
`https://api.bugcrowd.com/submissions`, `Semaphore(5)`, success=200/201.
### `examples/idor.yaml`: finding schema
`program, vuln_type, asset, affected_param, cwe, cvss_vector, summary,
steps_to_reproduce[], observed_result, poc_request, poc_response, impact,
remediation, references[]`.

## 6. cve-index CLI
`[project.scripts]`: **`cve-index = "cve_index.__main__:main"`** (single script).
`ingest --mode {full,update} [--days N=7]` (`__main__.py:73-77`) → `run_full(settings)`
(ingest.py:100) / `run_update(settings, days)` (133, bails if no live index).
Subparsers `required=True` → bare `cve-index` errors. **Emptiness check:** `GET /health`
(api.py:108-123) → `{status, elasticsearch:bool, vectors:int, semantic:bool}`;
`vectors == 0` ⇒ empty. `engine.cve_index_health(url)` already wraps it →
`{"up": bool(elasticsearch), "vectors": vectors}`. `serve` → `uvicorn.run("cve_index.api:app", ...)`; also `python -m cve_index serve`.

## 7. Test conventions
`[tool.pytest.ini_options]` per project: `pythonpath=["src"]`, `testpaths=["tests"]`;
recon + cve-index add `asyncio_mode="auto"` (+ pytest-asyncio). harness & bounty-reporter
use `asyncio.run(...)` inside sync tests (no asyncio plugin). Flat `tests/` with empty
`__init__.py`, `test_*.py` per module. **No conftest anywhere.**
- **harness mocking:** `monkeypatch.setattr(cli, "config_dir", lambda: tmp_path)`,
  `monkeypatch.setenv("HARNESS_HUNTS", str(tmp_path))`, swap async helpers
  (`_cve_index_healthy`), `monkeypatch.setattr(cli.subprocess,"Popen", FakeProc)`,
  `monkeypatch.setitem(sys.modules,"httpx",SimpleNamespace(get=fake_get))`.
- **bounty-reporter:** module-level `VULN` dict; feed `{"vulnerabilities":[]}` to
  `upload_report` so no POST fires; `monkeypatch.setenv("H1_IDENTIFIER", ...)`.
- **recon:** `@pytest.mark.asyncio`; stub at function boundary (`FakeProber.probe`,
  `monkeypatch.setattr("recon_orchestrator.subdomain_enum.fetch_crtsh_for_apex", ...)`);
  no respx/AsyncMock; ES never mocked (stubbed above the httpx boundary).

## 8. Humanizer + LLM: none in code today
No LLM API client anywhere in `src/` (grep clean). Every `httpx` call goes to
cve-index / H1 / Bugcrowd / ZAP / NVD / MITRE / crt.sh / Vercel / target host.
No `humanize` fn. Only ML = `cve-classifier` local torch QLoRA (`infer.py`
`AutoModelForCausalLM` + `PeftModel`, `model.generate`), behind `ComponentMissing`,
thread-worker only. **Humanizer = a NEW integration (needs an LLM backend).**

## File index
- front door: `harness/src/harness/__main__.py`
- engine: `harness/src/harness/engine.py`
- programs/store/paths/findings: `harness/src/harness/{programs,store,paths,findings}.py`
- TUI: `harness/src/harness/tui/app.py` (+ `app.tcss`)
- reporter: `bounty-reporter/src/bounty_reporter/{models,generator,uploader}.py`, `examples/idor.yaml`
- cve-index: `cve-index/src/cve_index/{__main__,ingest,api}.py`, `pyproject.toml`
- classifier: `cve-classifier/src/cve_classifier/infer.py`
