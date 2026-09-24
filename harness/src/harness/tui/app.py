"""The security-harness TUI: pick a program, run recon, browse ranked leads,
scaffold + render a report, classify CVEs — all menu/key driven."""
from __future__ import annotations

from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TextArea,
)
import os

from rich.text import Text

from .. import engine, findings_store, store
from ..findings import finding_template
from ..findings_store import FindingRecord
from ..paths import ensure_dirs, hunts_dir, programs_file
from ..programs import Program, Registry

DEFAULT_CVE_URL = "http://localhost:8080"


def _score_cell(score) -> Text:
    """Colour a priority score so high-value leads catch the eye in a table.

    A ranked list is only useful if the top of it stands out; a plain number
    makes a 95 look the same as a 10.
    """
    try:
        value = int(score)
    except (TypeError, ValueError):
        return Text(str(score or "-"), style="dim")
    if value >= 70:
        style = "bold red"
    elif value >= 40:
        style = "bold yellow"
    elif value >= 15:
        style = "green"
    else:
        style = "dim"
    return Text(str(value), style=style)


class AddProgramScreen(ModalScreen[dict | None]):
    """Modal form to define a new program."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Add program", id="dialog-title")
            yield Label("Import scope from HackerOne:", classes="form-section")
            yield Input(placeholder="program handle (e.g. security) — pulls scope for you",
                       id="f-handle")
            yield Label("— or enter it manually —", classes="form-divider")
            yield Input(placeholder="name (e.g. acme)", id="f-name")
            yield Input(placeholder="in-scope, comma sep (e.g. *.acme.com)", id="f-in")
            yield Input(placeholder="out-of-scope, comma sep (optional)", id="f-out")
            yield Input(placeholder="seeds, comma sep (optional)", id="f-seeds")
            yield Checkbox("Active testing — OWNED ASSETS ONLY", id="f-active")
            yield Checkbox("Use OWASP ZAP engine (needs active testing)", id="f-zap")
            with Horizontal(id="dialog-buttons"):
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return

        # ZAP implies active testing; active testing must be explicit.
        active = self.query_one("#f-active", Checkbox).value
        use_zap = self.query_one("#f-zap", Checkbox).value
        if use_zap:
            active = True

        # A handle takes the import path; the manual fields are ignored so the
        # two ways of adding a program never fight over the same submit.
        handle = self.query_one("#f-handle", Input).value.strip()
        if handle:
            self.dismiss({"import_handle": handle,
                          "active_tests": active, "use_zap": use_zap})
            return

        name = self.query_one("#f-name", Input).value.strip()
        if not name:
            self.app.notify("enter a HackerOne handle to import, or a name to add manually",
                           severity="error")
            return

        def split(box_id: str) -> list[str]:
            raw = self.query_one(box_id, Input).value
            return [p.strip() for p in raw.split(",") if p.strip()]

        self.dismiss({
            "name": name,
            "in_scope": split("#f-in"),
            "out_of_scope": split("#f-out"),
            "seeds": split("#f-seeds"),
            # Sensible defaults — the local cve-index, no seeds file. Both are
            # rarely changed and stay editable in programs.yaml for the odd case.
            "seeds_file": None,
            "cve_index_url": DEFAULT_CVE_URL,
            "active_tests": active,
            "use_zap": use_zap,
        })

    def action_cancel(self) -> None:
        self.dismiss(None)


class PromptScreen(ModalScreen[str | None]):
    """Generic single-line prompt modal (used for CVE search and classify)."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title: str, placeholder: str) -> None:
        super().__init__()
        self._title = title
        self._placeholder = placeholder

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._title, id="dialog-title")
            yield Input(placeholder=self._placeholder, id="q")
            with Horizontal(id="dialog-buttons"):
                yield Button("Go", variant="primary", id="go")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        else:
            self.dismiss(self.query_one("#q", Input).value.strip() or None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip() or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    """Yes/no modal. Defaults to No so a stray Enter never confirms."""

    BINDINGS = [
        Binding("escape", "no", "Cancel"),
        Binding("n", "no", "No"),
        Binding("y", "yes", "Yes"),
    ]

    def __init__(self, question: str, confirm_label: str = "Confirm",
                 destructive: bool = True) -> None:
        super().__init__()
        self._question = question
        self._confirm_label = confirm_label
        self._destructive = destructive

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self._question, id="dialog-title")
            with Horizontal(id="dialog-buttons"):
                yield Button(
                    self._confirm_label,
                    variant="error" if self._destructive else "primary",
                    id="yes",
                )
                yield Button("Cancel", id="no")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


class HelpScreen(ModalScreen[None]):
    """Keybinding reference and the recon → report workflow."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("q", "close", "Close"),
        Binding("question_mark", "close", "Close"),
    ]

    HELP = """[b]security-harness[/b]

[b]Workflow[/b]
  1. [b]a[/b] add a program — manually, or import its scope from HackerOne
  2. [b]r[/b] recon — probe hosts, collect ranked leads
  3. [b]v[/b] scan — correlate services against the CVE index
  4. [b]t[/b] triage — ranked findings across every program
  5. [b]w[/b] scaffold → fill in → [b]e[/b] render a report
  6. [b]u[/b] upload the report to HackerOne / Bugcrowd

[b]Programs[/b]              [b]Per lead[/b]
  a  add / import H1      s  search the CVE index
  i  import H1 scope      c  classify a description
  z  active/ZAP mode      w  scaffold a report
  d  delete (confirms)    e  render a report
  n  nightly: all progs

[b]Active testing[/b] (OWNED ASSETS ONLY) — [b]z[/b] cycles a program
  off -> active (built-in) -> active + ZAP -> off. Then [b]r[/b] recon runs
  it; ZAP findings land in the leads/triage. ZAP creds come from ~/.harness/.env.

[b]Anywhere[/b]
  t  triage      u  upload      q  quit      ?  this help

[dim]Only run recon/scan against programs whose policy allows
automated scanning.[/dim]"""

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Static(self.HELP, id="help-body")
            yield Label("[dim]esc / q / ? to close[/dim]")

    def action_close(self) -> None:
        self.dismiss(None)


class TriageScreen(ModalScreen[None]):
    """Screen showing a ranked table of vulnerability findings across all programs."""

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
        Binding("q", "cancel", "Close"),   # also allow q to close the modal
    ]

    def __init__(self, registry: Registry) -> None:
        super().__init__()
        self.registry = registry

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield DataTable(id="triage-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#triage-table", DataTable)
        table.add_columns("Program", "Score", "Host:Port", "Service", "CVE Count", "Exploit", "Sensitive")
        self._populate_table()

    def _populate_table(self) -> None:
        table = self.query_one("#triage-table", DataTable)
        table.clear()
        for prog_name in self.registry.names():
            vulns = store.load_vulns(prog_name)
            if not vulns:
                continue
            # Sort by priority_score descending
            sorted_vulns = sorted(vulns, key=lambda v: v.get("priority_score", 0), reverse=True)
            for v in sorted_vulns[:20]:  # limit to top 20 per program for brevity
                score = v.get("priority_score", 0)
                # Pick first service if multiple (should be one per vuln)
                service_info = v.get("service", {})
                host = service_info.get("host", "")
                port = service_info.get("port", "")
                scheme = service_info.get("scheme", "")
                hostport = f"{host}:{port}" if port else host
                service_desc = f"{scheme.upper()} {service_info.get('server','')} {service_info.get('powered_by','')}".strip()
                cves = v.get("cves", [])
                cve_count = len(cves)
                has_exploit = any(c.get("exploit_available") for c in cves)
                exploit_flag = Text("✓ EXPLOIT", style="bold red") if has_exploit else Text("")
                # Sensitive flag: check if we stored extra fields (we will add later)
                sensitive_flag = (
                    Text("✓", style="bold yellow")
                    if v.get("sensitive_paths") or v.get("cookies") or v.get("cors_issues")
                    else Text("")
                )
                table.add_row(
                    prog_name,
                    _score_cell(score),
                    hostport,
                    service_desc,
                    str(cve_count),
                    exploit_flag,
                    sensitive_flag,
                    key=f"{prog_name}_{hostport}"
                )

    def action_cancel(self) -> None:
        self.dismiss(None)


def _status_cell(status: str) -> Text:
    """Colour a finding's status so the review queue reads as a worklist."""
    styles = {
        "needs_check": "bold yellow",
        "ready": "bold green",
        "real": "bold red",
        "false": "dim",
        "duplicate": "dim",
    }
    return Text(status, style=styles.get(status, ""))


def collect_findings(registry: Registry) -> list[FindingRecord]:
    """Every stored finding across all programs, ordered as a triage worklist.

    A fresh finding still needing a human sits at the top; one already ruled
    real / false / duplicate sinks below it. Within a status, higher priority
    comes first.
    """
    out: list[FindingRecord] = []
    for prog_name in registry.names():
        out.extend(findings_store.load_findings(prog_name))
    order = {"needs_check": 0, "ready": 1, "real": 2, "duplicate": 3, "false": 4}
    out.sort(key=lambda r: (order.get(r.status, 9), -r.priority_score))
    return out


class FindingDetailScreen(ModalScreen[None]):
    """Verify a finding, draft its humanized report, and submit it.

    Fill in the evidence a passive scan can't know — what you confirmed by hand —
    then Ctrl+D to preview the humanized report, Ctrl+S to submit (twice, to
    confirm). Nothing is submitted without your keypress, and the uploader
    refuses anything missing real evidence.
    """

    BINDINGS = [
        Binding("escape", "close", "Back"),
        Binding("ctrl+d", "draft", "Draft report"),
        Binding("ctrl+s", "submit", "Submit"),
    ]

    def __init__(self, record: FindingRecord) -> None:
        super().__init__()
        self.record = record
        self._confirm = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        ev = self.record.evidence or {}
        with VerticalScroll():
            signals = "\n".join(f"• {s}" for s in (self.record.signals or [])) or "—"
            yield Static(
                f"[b]{self.record.host}[/b]  {self.record.url}\n"
                f"[dim]what recon saw:[/dim]\n{signals}",
                id="context",
            )
            yield Label("Vulnerability type")
            yield Input(value=ev.get("vuln_type", ""), id="vuln_type",
                        placeholder="e.g. Reflected XSS")
            yield Label("Asset (URL / endpoint / parameter)")
            yield Input(value=ev.get("asset", self.record.url or self.record.host),
                        id="asset")
            yield Label("Steps to reproduce (one per line)")
            yield TextArea("\n".join(ev.get("steps_to_reproduce", [])), id="steps")
            yield Label("Observed result (what you actually saw)")
            yield Input(value=ev.get("observed_result", ""), id="observed")
            yield Label("Impact")
            yield Input(value=ev.get("impact", ""), id="impact")
            yield Static("", id="preview")
        yield Footer()

    def _evidence(self) -> dict:
        steps = [line for line in self.query_one("#steps", TextArea).text.splitlines()
                 if line.strip()]
        return {
            "program": self.record.program,
            "vuln_type": self.query_one("#vuln_type", Input).value.strip(),
            "asset": (self.query_one("#asset", Input).value.strip()
                      or self.record.url or self.record.host),
            "steps_to_reproduce": steps,
            "observed_result": self.query_one("#observed", Input).value.strip(),
            "impact": self.query_one("#impact", Input).value.strip(),
        }

    def _persist(self, evidence: dict) -> None:
        findings_store.set_evidence(self.record.program, self.record.id, evidence)

    def _show(self, text: str) -> None:
        self.query_one("#preview", Static).update(text)

    def action_draft(self) -> None:
        self._confirm = False
        evidence = self._evidence()
        self._persist(evidence)
        try:
            markdown = engine.draft_report(evidence)
        except ValueError as exc:
            self._show(f"Can't draft yet — {exc}")
            return
        self._show(markdown)

    def action_submit(self) -> None:
        evidence = self._evidence()
        self._persist(evidence)
        required = ("vuln_type", "steps_to_reproduce", "observed_result", "impact")
        missing = [f for f in required if not evidence.get(f)]
        if missing:
            self._confirm = False
            self._show("Fill in before submitting: " + ", ".join(missing))
            return
        if not self._confirm:
            self._confirm = True
            self._show(f"⚠️  Submit to program '{self.record.program}'? "
                       "Press Ctrl+S again to confirm.")
            return
        self._confirm = False
        h1_key = os.getenv("H1_API_KEY")
        bc_key = os.getenv("BC_API_KEY")
        if not (h1_key or bc_key):
            self._show("No API keys set — add H1_IDENTIFIER + H1_API_KEY (or "
                       "BC_API_KEY) to ~/.harness/.env, then submit again.")
            return
        try:
            result = engine.submit_finding(
                evidence, self.record.program,
                h1_key=h1_key, bc_key=bc_key,
                h1_identifier=os.getenv("H1_IDENTIFIER"),
            )
        except Exception as exc:  # noqa: BLE001 - surface any submit error to the operator
            self._show(f"Submit failed: {exc}")
            return
        findings_store.update_status(self.record.program, self.record.id,
                                     "real", note="submitted")
        self._show(f"✅ submitted. {result}")

    def action_close(self) -> None:
        self._persist(self._evidence())
        self.dismiss(None)


class FindingsScreen(ModalScreen[None]):
    """The review queue: every finding across all programs, marked in place.

    r / f / x mark the highlighted finding real / false / duplicate and persist
    immediately; escape or q closes. The autonomous runner fills this queue; the
    operator works it here instead of editing files.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Close"),
        Binding("q", "cancel", "Close"),
        Binding("r", "mark_real", "Real"),
        Binding("f", "mark_false", "False"),
        Binding("x", "mark_duplicate", "Dup"),
    ]

    def __init__(self, registry: Registry) -> None:
        super().__init__()
        self.registry = registry
        self._ordered: list[tuple[str, str]] = []  # row index -> (program, finding id)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield DataTable(id="findings-table", cursor_type="row")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.add_columns("Program", "Status", "Score", "Host", "Findings", "Top signal")
        self._populate_table()

    def _populate_table(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        self._ordered = []
        for record in collect_findings(self.registry):
            host = record.host or (record.service or {}).get("host", "")
            signals = record.signals or []
            top = signals[0] if signals else "—"
            if len(top) > 61:
                top = top[:60] + "…"
            self._ordered.append((record.program, record.id))
            table.add_row(
                record.program,
                _status_cell(record.status),
                _score_cell(record.priority_score),
                host,
                str(len(signals)),
                top,
                key=record.id,
            )

    def _mark(self, status: str) -> None:
        table = self.query_one("#findings-table", DataTable)
        idx = table.cursor_row
        if idx is None or idx < 0 or idx >= len(self._ordered):
            return
        program, fid = self._ordered[idx]
        findings_store.update_status(program, fid, status)
        self._populate_table()

    def on_data_table_row_selected(self, event) -> None:
        """Enter on a row opens that finding to verify, draft, and submit."""
        row_key = event.row_key.value if event.row_key is not None else None
        for program, fid in self._ordered:
            if fid == row_key:
                record = findings_store.get_finding(program, fid)
                if record is not None:
                    self.app.push_screen(FindingDetailScreen(record))
                return

    def action_mark_real(self) -> None:
        self._mark("real")

    def action_mark_false(self) -> None:
        self._mark("false")

    def action_mark_duplicate(self) -> None:
        self._mark("duplicate")

    def action_cancel(self) -> None:
        self.dismiss(None)


class HarnessApp(App[None]):
    CSS_PATH = "app.tcss"
    TITLE = "security-harness"
    # The footer only has room for the hot path — the rest are hidden
    # (show=False) but still work, and `?` lists every one. This keeps the
    # footer on one line instead of running off the edge of the terminal.
    BINDINGS = [
        Binding("r", "recon", "Recon"),
        Binding("v", "scan", "Scan"),
        Binding("t", "triage", "Triage"),
        Binding("f", "findings", "Findings"),
        Binding("u", "upload", "Upload"),
        Binding("a", "add", "Add"),
        Binding("question_mark", "help", "Help", key_display="?"),
        Binding("q", "quit", "Quit"),
        # hidden from the footer, discoverable via `?`
        Binding("i", "import_scope", "Import H1 scope", show=False),
        Binding("z", "toggle_active", "Active/ZAP mode", show=False),
        Binding("n", "nightly", "Nightly run", show=False),
        Binding("s", "search", "Search CVEs", show=False),
        Binding("w", "report", "Scaffold report", show=False),
        Binding("e", "export", "Render report", show=False),
        Binding("c", "classify", "Classify", show=False),
        Binding("d", "delete", "Delete program", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        ensure_dirs()
        self.registry = Registry.load(programs_file())
        self.current_program: str | None = None
        self.current_leads: list[dict] = []

    # ---- layout --------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("checking components…", id="status")
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("Programs", classes="panel-title")
                yield DataTable(id="programs", cursor_type="row")
            with Vertical(id="main"):
                yield Label("Leads", classes="panel-title")
                yield DataTable(id="leads", cursor_type="row")
                yield Static("Select a program and press [b]r[/b] to run recon.",
                             id="detail")
        yield Footer()

    def on_mount(self) -> None:
        programs = self.query_one("#programs", DataTable)
        programs.add_columns("Program", "Leads", "Last run")
        leads = self.query_one("#leads", DataTable)
        leads.add_columns("Score", "Host", "Why", "CVEs")
        self.refresh_programs()
        self.refresh_status()
        # Auto-open triage if requested via environment variable (set by harness global).
        # pop() so a second app run in the same process doesn't re-trigger it, and
        # defer the push until after the first refresh — pushing a screen mid-mount
        # leaves the modal on top while focus stays on the main screen.
        if os.environ.pop("HARNESS_AUTO_OPEN_TRIAGE", None) == "1":
            self.call_after_refresh(lambda: self.push_screen(TriageScreen(self.registry)))

    def action_findings(self) -> None:
        """Open the review queue: every finding across all programs."""
        self.push_screen(FindingsScreen(self.registry))

    # ---- component status bar -----------------------------------------
    def _cve_url(self) -> str:
        prog = self.registry.get(self.current_program) if self.current_program else None
        return (prog.cve_index_url if prog else None) or DEFAULT_CVE_URL

    @work(exclusive=True, group="status")
    async def refresh_status(self) -> None:
        avail = engine.available()
        health = await engine.cve_index_health(self._cve_url())

        def mark(ok: bool) -> str:
            return "[green]✓[/green]" if ok else "[red]✗[/red]"

        if health["up"]:
            vec = health["vectors"]
            idx = f"[green]● up[/green] ({vec:,} docs)" if isinstance(vec, int) else "[green]● up[/green]"
        else:
            idx = "[red]● down[/red]"
        text = (
            f" recon {mark(avail['recon'])}  ·  "
            f"cve-index {idx}  ·  "
            f"classifier {mark(avail['classifier'])}  ·  "
            f"reporter {mark(avail['reporter'])}"
        )
        self.query_one("#status", Static).update(text)

    # ---- data refresh --------------------------------------------------
    def refresh_programs(self) -> None:
        table = self.query_one("#programs", DataTable)
        table.clear()
        for name in self.registry.names():
            prog = self.registry.get(name)
            n_leads = len(store.load_leads(name))
            last = store.last_run(name)
            last_str = last.strftime("%m-%d %H:%M") if last else "-"
            # Mark active-testing programs so an armed target is never a surprise.
            if prog and prog.use_zap:
                label = Text.assemble(name, ("  ⚡ZAP", "bold red"))
            elif prog and prog.active_tests:
                label = Text.assemble(name, ("  ⚡active", "bold yellow"))
            else:
                label = name
            table.add_row(label, str(n_leads) if n_leads else "-", last_str, key=name)
        if self.registry.names() and self.current_program is None:
            self.select_program(self.registry.names()[0])

    def select_program(self, name: str) -> None:
        self.current_program = name
        self.current_leads = store.load_leads(name)
        self.refresh_leads()
        self.refresh_status()

    def refresh_leads(self) -> None:
        table = self.query_one("#leads", DataTable)
        table.clear()
        for i, lead in enumerate(self.current_leads):
            cves = len(lead.get("cve_candidates", []))
            why = "; ".join(lead.get("signals", []))[:60] or "-"
            table.add_row(
                _score_cell(lead.get("priority_score")),
                lead.get("host", ""),
                why,
                Text(str(cves), style="bold cyan") if cves else Text("-", style="dim"),
                key=str(i),
            )
        title = self.current_program or "-"
        self.query_one("#detail", Static).update(
            f"Program [b]{title}[/b] — {len(self.current_leads)} leads. "
            "[b]r[/b] recon · [b]v[/b] scan vulns · [b]w[/b] scaffold · [b]e[/b] render · [b]c[/b] classify."
        )

    # ---- selection events ---------------------------------------------
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "programs":
            self.select_program(str(event.row_key.value))
        elif event.data_table.id == "leads":
            self.show_lead_detail(int(event.row_key.value))

    def show_lead_detail(self, index: int) -> None:
        if index >= len(self.current_leads):
            return
        lead = self.current_leads[index]
        lines = [f"[b]{lead.get('host')}[/b]  (score {lead.get('priority_score')})"]
        for sig in lead.get("signals", []):
            lines.append(f"  • {sig}")
        for cve in lead.get("cve_candidates", []):
            lines.append(
                f"  CVE {cve.get('cve_id')} "
                f"[{cve.get('cvss_severity') or '?'}] {cve.get('product')} "
                f"{cve.get('version') or ''}"
            )
        lines.append(f"[dim]{lead.get('note', '')}[/dim]")
        self.query_one("#detail", Static).update("\n".join(lines))

    def _selected_lead_index(self) -> int:
        table = self.query_one("#leads", DataTable)
        try:
            key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            return int(key.value)
        except Exception:  # noqa: BLE001
            return 0

    # ---- actions -------------------------------------------------------
    def action_add(self) -> None:
        def handle(result: dict | None) -> None:
            if not result:
                return
            # A HackerOne handle routes to the import flow instead of a manual add.
            if "import_handle" in result:
                self._do_import_scope(result["import_handle"],
                                      active_tests=result.get("active_tests", False),
                                      use_zap=result.get("use_zap", False))
                return
            self.registry.add(Program(**result))
            self.registry.save(programs_file())
            self.current_program = result["name"]
            self.refresh_programs()
            self.select_program(result["name"])
            self.notify(f"added program '{result['name']}'")

        self.push_screen(AddProgramScreen(), handle)

    def action_import_scope(self) -> None:
        """Prompt for a HackerOne handle and import its scope into the registry.

        Saves running `harness import-scope` outside the TUI. Remember the
        pipeline scans everything in the registry, so only add a program here
        if it permits automated scanning — check its policy first.
        """
        def handle(result: str | None) -> None:
            if result:
                self._do_import_scope(result.strip())

        self.push_screen(
            PromptScreen("Import HackerOne scope", "program handle, e.g. security"),
            handle,
        )

    @work(exclusive=True)
    async def _do_import_scope(self, program_handle: str,
                               active_tests: bool = False, use_zap: bool = False) -> None:
        try:
            from recon_orchestrator.hackerone_scope import fetch_structured_scopes
        except ImportError:
            self.notify("recon-orchestrator not installed", severity="error")
            return

        identifier = os.environ.get("H1_IDENTIFIER")
        token = os.environ.get("H1_API_KEY")
        if not identifier or not token:
            self.notify(
                "set H1_IDENTIFIER and H1_API_KEY in ~/.harness/.env first",
                severity="error",
            )
            return

        self.notify(f"fetching scope for '{program_handle}'…")
        skipped: list[str] = []
        try:
            in_scope, out_scope = await fetch_structured_scopes(
                program_handle, identifier, token, skipped=skipped
            )
        except (PermissionError, LookupError, ValueError) as exc:
            self.notify(str(exc), severity="error")
            return
        except Exception as exc:  # noqa: BLE001
            self.notify(f"import failed: {exc}", severity="error")
            return

        if not in_scope and not out_scope:
            self.notify(f"no host-shaped assets in '{program_handle}'", severity="warning")
            return

        existing = self.registry.get(program_handle)
        if existing is None:
            seeds = [p for p in in_scope if not p.startswith("*")]
            self.registry.add(Program(
                name=program_handle, in_scope=in_scope, out_of_scope=out_scope,
                seeds=seeds, seeds_file=None, cve_index_url=DEFAULT_CVE_URL,
                active_tests=active_tests, use_zap=use_zap,
                h1_handle=program_handle,
            ))
            verb = f"created with {len(seeds)} seed(s)"
        else:
            self.registry.add(existing.model_copy(update={
                "in_scope": in_scope, "out_of_scope": out_scope,
                "h1_handle": program_handle,
            }))
            verb = "scope refreshed (seeds kept)"

        self.registry.save(programs_file())
        self.current_program = program_handle
        self.refresh_programs()
        self.select_program(program_handle)

        extra = f" — {len(skipped)} non-host asset(s), review by hand" if skipped else ""
        self.notify(
            f"'{program_handle}': {len(in_scope)} in, {len(out_scope)} out, {verb}{extra}. "
            f"Check the program's automation policy before scanning.",
            severity="information",
            timeout=10,
        )

    def action_nightly(self) -> None:
        """Run the nightly pipeline for all programs (sub‑domain enum → port sweep → CPE → etc.)."""
        if not self.registry.names():
            self.notify("no programs defined", severity="warning")
            return
        self.notify("starting nightly run for all programs…")
        # Run in a worker so the UI stays responsive
        self._run_nightly_all()

    @work(exclusive=True)
    async def _run_nightly_all(self) -> None:
        """Run recon + vuln scan for every program, then refresh the UI.

        This drives the same engine pipeline as `harness global`, so results
        land in the harness store and the tables update. The nightly package's
        own runner keeps its results internally and would leave these views
        showing stale data.
        """
        names = self.registry.names()
        if not names:
            self.notify("no programs configured", severity="warning")
            return

        ran = failed = 0
        for i, name in enumerate(names, 1):
            program = self.registry.get(name)
            self.notify(f"[{i}/{len(names)}] {name}: recon…")
            try:
                leads = await engine.run_recon(program)
                store.save_leads(name, leads)
                vulns = await engine.scan_for_vulns(program, leads)
                store.save_vulns(name, vulns)
                ran += 1
            except Exception as exc:  # noqa: BLE001 - one program must not sink the run
                failed += 1
                self.notify(f"{name}: {exc}", severity="error")

        if self.current_program:
            self.current_leads = store.load_leads(self.current_program)
            self.refresh_leads()
        self.refresh_programs()
        self.notify(
            f"nightly run finished: {ran} ok, {failed} failed",
            severity="error" if failed else "information",
        )

    def action_triage(self) -> None:
        """Open the triage dashboard showing ranked findings across all programs."""
        if not self.registry.names():
            self.notify("no programs defined", severity="warning")
            return
        self.push_screen(TriageScreen(self.registry))

    def action_upload(self) -> None:
        """Generate a batch report and upload it to configured platforms.

        Keys come from ~/.harness/.env (H1_API_KEY / BC_API_KEY), so the token
        is never typed on screen. Uploading submits real reports to a real
        program, so it always confirms first.
        """
        if not self.current_program:
            self.notify("no program selected", severity="warning")
            return
        vulns = store.load_vulns(self.current_program)
        if not vulns:
            self.notify("no findings to upload — run scan first (press 'v')",
                       severity="warning")
            return

        h1_key = os.environ.get("H1_API_KEY")
        bc_key = os.environ.get("BC_API_KEY")
        if not h1_key and not bc_key:
            self.notify(
                "no API keys — set H1_API_KEY / BC_API_KEY in ~/.harness/.env",
                severity="error",
            )
            return

        targets = ", ".join(
            n for n, k in (("HackerOne", h1_key), ("Bugcrowd", bc_key)) if k
        )

        def confirmed(ok: bool | None) -> None:
            if ok:
                self._do_upload(h1_key, bc_key)

        self.push_screen(
            ConfirmScreen(
                f"Submit {len(vulns)} finding(s) for "
                f"'{self.current_program}' to {targets}?",
                confirm_label="Submit",
            ),
            confirmed,
        )

    def _do_upload(self, h1_key: str | None, bc_key: str | None) -> None:
        """Internal: generate report and call uploader."""
        self.notify("generating batch report…")
        try:
            # Load vulns (if any) – if none, we can still upload empty? better to warn.
            vulns = store.load_vulns(self.current_program)
            if not vulns:
                self.notify("no vulnerability findings to upload – run scan first (press 'v')", severity="warning")
                return
            # Generate report
            from ..engine import render_batch_report
            out_dir = hunts_dir() / self.current_program
            report_path = render_batch_report(self.current_program, vulns, out_dir)
            self.notify(f"report generated: {report_path}")
            # Upload. bounty_reporter is a sibling top-level package, not a
            # submodule of harness — a relative import does not resolve.
            from bounty_reporter.uploader import upload_report
            # render_batch_report returns the Markdown path; upload_report parses
            # JSON. Both are written side by side in out_dir.
            res = upload_report(
                report_path.with_suffix(".json"), self.current_program, h1_key, bc_key
            )
            # Report what actually happened rather than assuming success.
            sent = sum(p["sent"] for p in res.values())
            failed = sum(p["failed"] for p in res.values())
            errors = [e for p in res.values() for e in p["errors"]]
            if failed or errors:
                detail = errors[0] if errors else "see console"
                self.notify(
                    f"upload: {sent} sent, {failed} failed — {detail}",
                    severity="error",
                )
            else:
                self.notify(f"upload completed: {sent} sent", severity="information")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"upload failed: {exc}", severity="error")

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_toggle_active(self) -> None:
        """Cycle the selected program's active-testing mode:
        off -> built-in active -> ZAP -> off. Arming asks for confirmation,
        because it sends crafted attack traffic — owned assets only."""
        if not self.current_program:
            self.notify("no program selected", severity="warning")
            return
        name = self.current_program
        prog = self.registry.get(name)
        if prog is None:
            return

        # Determine the next state in the cycle.
        if not prog.active_tests:
            next_active, next_zap, label = True, False, "active (built-in)"
        elif prog.active_tests and not prog.use_zap:
            next_active, next_zap, label = True, True, "active + ZAP"
        else:
            next_active, next_zap, label = False, False, "off"

        def apply() -> None:
            self.registry.add(prog.model_copy(
                update={"active_tests": next_active, "use_zap": next_zap}))
            self.registry.save(programs_file())
            self.refresh_programs()
            self.select_program(name)
            self.notify(f"'{name}': active testing -> {label}",
                        severity="warning" if next_active else "information")

        if next_active and not prog.active_tests:
            # Arming from off — confirm, since this enables attack traffic.
            def confirmed(ok: bool | None) -> None:
                if ok:
                    apply()
            self.push_screen(
                ConfirmScreen(
                    f"Enable active testing on '{name}'? This sends crafted "
                    "attack traffic — only for assets you own.",
                    confirm_label="Enable"),
                confirmed,
            )
        else:
            apply()

    def action_delete(self) -> None:
        if not self.current_program:
            self.notify("no program selected", severity="warning")
            return
        name = self.current_program

        def confirmed(ok: bool | None) -> None:
            if not ok:
                return
            if self.registry.remove(name):
                self.registry.save(programs_file())
                self.current_program = None
                self.current_leads = []
                self.refresh_programs()
                self.refresh_leads()
                self.notify(f"deleted program '{name}'", severity="warning")

        self.push_screen(
            ConfirmScreen(f"Delete program '{name}'? This cannot be undone.",
                         confirm_label="Delete"),
            confirmed,
        )

    def action_recon(self) -> None:
        """Handler for the `r` binding. The worker existed but nothing called
        it, so the key advertised in the footer did nothing at all."""
        if not self.current_program:
            self.notify("no program selected", severity="warning")
            return
        program = self.registry.get(self.current_program)
        runnable, why = program.is_runnable()
        if not runnable:
            self.notify(f"can't run: {why}", severity="error")
            return
        self._run_recon(program)

    def action_scan(self) -> None:
        if not self.current_program:
            self.notify("no program selected", severity="warning")
            return
        program = self.registry.get(self.current_program)
        runnable, why = program.is_runnable()
        if not runnable:
            self.notify(f"can't run: {why}", severity="error")
            return
        self._run_scan(program)

    @work(exclusive=True)
    async def _run_recon(self, program: Program) -> None:
        self.notify(f"running recon on '{program.name}'…")
        self.query_one("#detail", Static).update(
            f"[b]running recon on {program.name}[/b] — probing hosts, this may take a bit…"
        )
        try:
            leads = await engine.run_recon(program)
        except engine.ComponentMissing as exc:
            self.notify(str(exc), severity="error")
            return
        except Exception as exc:  # noqa: BLE001
            self.notify(f"recon failed: {exc}", severity="error")
            return
        store.save_leads(program.name, leads)
        self.current_leads = leads
        self.refresh_leads()
        self.refresh_programs()
        self.notify(f"recon done: {len(leads)} candidate leads", severity="information")

    @work(exclusive=True)
    async def _run_scan(self, program: Program) -> None:
        self.notify(f"scanning '{program.name}' for vulnerabilities…")
        self.query_one("#detail", Static).update(
            f"[b]scanning {program.name}[/b] — running recon + CVE search, please wait…"
        )
        try:
            # Re-run recon to ensure fresh data
            leads = await engine.run_recon(program)
            store.save_leads(program.name, leads)
            self.current_leads = leads
            self.refresh_leads()

            # Run vuln scan and persist it — without this the findings vanish
            # and Triage (which reads from storage) has nothing to show.
            vulns = await engine.scan_for_vulns(program, leads)
            store.save_vulns(program.name, vulns)
            self.refresh_programs()

            if vulns:
                msg = (f"[b]scan done[/b] — {len(vulns)} finding(s). "
                       "Press [b]t[/b] to open Triage.")
                self.notify(
                    f"found {len(vulns)} finding(s) — press 't' for triage",
                    severity="information",
                )
            else:
                msg = "[b]scan done[/b] — no findings."
                self.notify("scan complete: no findings", severity="information")
            self.query_one("#detail", Static).update(msg)
        except engine.ComponentMissing as exc:
            self.notify(str(exc), severity="error")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"scan failed: {exc}", severity="error")

    def action_search(self) -> None:
        cve_url = self._cve_url()

        def handle(query: str | None) -> None:
            if query:
                self._run_search(query, cve_url)

        self.push_screen(PromptScreen("Search cve-index",
                                      "e.g. nginx 1.18 path traversal"), handle)

    @work(exclusive=True)
    async def _run_search(self, query: str, cve_url: str) -> None:
        self.notify(f"searching cve-index for '{query}'…")
        try:
            results = await engine.search_cve(query, cve_url)
        except Exception as exc:  # noqa: BLE001
            self.notify(f"search failed ({cve_url}): {exc}", severity="error")
            return
        lines = [f"[b]cve-index: {len(results)} results for '{query}'[/b]"]
        for hit in results[:12]:
            src = hit.get("source", {})
            lines.append(
                f"  {src.get('id', hit.get('id'))} "
                f"[{src.get('cvss_severity') or '?'}] "
                f"{(src.get('description') or '')[:70]}"
            )
        self.query_one("#detail", Static).update("\n".join(lines))

    def action_report(self) -> None:
        if not self.current_program or not self.current_leads:
            self.notify("no lead to scaffold", severity="warning")
            return
        lead = self.current_leads[self._selected_lead_index()]
        template = finding_template(self.current_program, lead)
        out_dir = hunts_dir() / self.current_program
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_host = lead.get("host", "lead").replace("/", "_")
        path = out_dir / f"finding-{safe_host}.yaml"
        Path(path).write_text(template, encoding="utf-8")
        self.query_one("#detail", Static).update(
            f"[b]scaffold written:[/b] {path}\n"
            "Fill the TODOs from your manual testing, then press [b]e[/b] to render\n"
            "the HackerOne + Bugcrowd + Markdown report."
        )
        self.notify(f"report scaffold → {path}")

    def action_export(self) -> None:
        if not self.current_program or not self.current_leads:
            self.notify("no lead selected", severity="warning")
            return
        lead = self.current_leads[self._selected_lead_index()]
        safe_host = lead.get("host", "lead").replace("/", "_")
        path = hunts_dir() / self.current_program / f"finding-{safe_host}.yaml"
        if not path.exists():
            self.notify("no scaffold yet — press [w] first, then fill it in",
                        severity="warning")
            return
        try:
            result = engine.render_report(str(path))
        except engine.ComponentMissing as exc:
            self.notify(str(exc), severity="error")
            return
        except ValueError as exc:
            self.query_one("#detail", Static).update(
                f"[yellow]can't render yet:[/yellow] {exc}"
            )
            self.notify("scaffold still has TODOs", severity="warning")
            return
        except Exception as exc:  # noqa: BLE001
            self.notify(f"render failed: {exc}", severity="error")
            return
        self.query_one("#detail", Static).update(
            f"[b]report rendered[/b] — rating {result['rating']} "
            f"(CVSS {result['cvss']})\n{result['out_dir']}/\n"
            f"  {result['fingerprint']}.md · .hackerone.json · .bugcrowd.json"
        )
        self.notify(f"report → {result['out_dir']}")

    def action_classify(self) -> None:
        def handle(description: str | None) -> None:
            if description:
                self._run_classify(description)

        self.push_screen(PromptScreen("Classify a CVE/finding description",
                                      "paste a vulnerability description"), handle)

    @work(thread=True, exclusive=True)
    def _run_classify(self, description: str) -> None:
        self.call_from_thread(self.notify, "classifying…")
        try:
            result = engine.classify(description)
            msg = (f"[b]classification[/b]\n  severity: {result['severity']}\n"
                   f"  cwe: {result['cwe']}\n[dim]raw: {result.get('raw', '')[:120]}[/dim]")
        except engine.ComponentMissing as exc:
            msg = f"[yellow]classifier unavailable:[/yellow] {exc}"
        except Exception as exc:  # noqa: BLE001
            msg = (f"[yellow]classifier not ready:[/yellow] {exc}\n"
                   "[dim]needs a trained adapter (see cve-classifier README).[/dim]")
        self.call_from_thread(self.query_one("#detail", Static).update, msg)


def main() -> None:
    HarnessApp().run()


if __name__ == "__main__":
    main()
