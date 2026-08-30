"""The security-harness TUI: pick a program, run recon, browse ranked leads,
scaffold + render a report, classify CVEs — all menu/key driven."""
from __future__ import annotations

from pathlib import Path
from typing import List, Dict, Any

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from .. import engine, store
from ..findings import finding_template
from ..paths import ensure_dirs, hunts_dir, programs_file
from ..programs import Program, Registry

DEFAULT_CVE_URL = "http://localhost:8080"


class AddProgramScreen(ModalScreen[dict | None]):
    """Modal form to define a new program."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Add program", id="dialog-title")
            yield Input(placeholder="name (e.g. acme)", id="f-name")
            yield Input(placeholder="in-scope, comma sep (e.g. *.acme.com)", id="f-in")
            yield Input(placeholder="out-of-scope, comma sep (optional)", id="f-out")
            yield Input(placeholder="seeds, comma sep (optional)", id="f-seeds")
            yield Input(placeholder="seeds file path (optional)", id="f-seedsfile")
            yield Input(placeholder="cve-index url (e.g. http://localhost:8080)", id="f-cve")
            with Horizontal(id="dialog-buttons"):
                yield Button("Save", variant="primary", id="save")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        name = self.query_one("#f-name", Input).value.strip()
        if not name:
            self.app.notify("name is required", severity="error")
            return

        def split(box_id: str) -> list[str]:
            raw = self.query_one(box_id, Input).value
            return [p.strip() for p in raw.split(",") if p.strip()]

        self.dismiss({
            "name": name,
            "in_scope": split("#f-in"),
            "out_of_scope": split("#f-out"),
            "seeds": split("#f-seeds"),
            "seeds_file": self.query_one("#f-seedsfile", Input).value.strip() or None,
            "cve_index_url": self.query_one("#f-cve", Input).value.strip() or None,
        })

    def action_cancel(self) -> None:
        self.dismiss(None)


class PromptScreen(ModalScreen[str | None]):
    """Generic single-line prompt modal (used for CVE search and classify)."""


class TriageScreen(ModalScreen[None]):
    """Screen showing a ranked table of vulnerability findings across all programs."""

    BINDINGS = [Binding("escape", "cancel", "Close")]

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
                exploit_flag = "✓" if any(c.get("exploit_available") for c in cves) else ""
                # Sensitive flag: check if we stored extra fields (we will add later)
                sensitive_flag = "✓" if v.get("sensitive_paths") or v.get("cookies") or v.get("cors_issues") else ""
                table.add_row(
                    prog_name,
                    str(score),
                    hostport,
                    service_desc,
                    str(cve_count),
                    exploit_flag,
                    sensitive_flag,
                    key=f"{prog_name}_{hostport}"
                )


def main() -> None:
    HarnessApp().run()

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


class HarnessApp(App[None]):
    CSS_PATH = "app.tcss"
    TITLE = "security-harness"
    BINDINGS = [
        Binding("n", "nightly", "Nightly Run"),
        Binding("t", "triage", "Triage"),
        Binding("r", "recon", "Recon"),
        Binding("v", "scan", "Scan Vulns"),
        Binding("s", "search", "Search CVEs"),
        Binding("w", "report", "Scaffold report"),
        Binding("e", "export", "Render report"),
        Binding("c", "classify", "Classify"),
        Binding("a", "add", "Add program"),
        Binding("d", "delete", "Delete program"),
        Binding("u", "upload", "Upload Report"),
        Binding("q", "quit", "Quit"),
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
            n_leads = len(store.load_leads(name))
            last = store.last_run(name)
            last_str = last.strftime("%m-%d %H:%M") if last else "-"
            table.add_row(name, str(n_leads) if n_leads else "-", last_str, key=name)
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
                str(lead.get("priority_score", "")),
                lead.get("host", ""),
                why,
                str(cves) if cves else "-",
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
            self.registry.add(Program(**result))
            self.registry.save(programs_file())
            self.current_program = result["name"]
            self.refresh_programs()
            self.select_program(result["name"])
            self.notify(f"added program '{result['name']}'")

        self.push_screen(AddProgramScreen(), handle)

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
        """Worker that runs the nightly orchestrator once and updates UI."""
        try:
            # Import here to avoid circular import issues
            from ..recon_orchestrator.nightly.orchestrator import run_all_once
            run_all_once()  # this function runs synchronously (asyncio.run inside)
            # After run, refresh data for the currently selected program (if any)
            if self.current_program:
                self.current_leads = store.load_leads(self.current_program)
                self.refresh_leads()
                self.refresh_programs()
            self.notify("nightly run completed", severity="information")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"nightly run failed: {exc}", severity="error")

    def action_triage(self) -> None:
        """Open the triage dashboard showing ranked findings across all programs."""
        if not self.registry.names():
            self.notify("no programs defined", severity="warning")
            return
        self.push_screen(TriageScreen(self.registry))

    def action_upload(self) -> None:
        """Generate a batch report and upload it to configured platforms."""
        if not self.current_program:
            self.notify("no program selected", severity="warning")
            return
        # Ensure we have leads (run recon if needed)
        if not self.current_leads:
            self.notify("no leads available – run recon first (press 'r')", severity="warning")
            return
        # Prompt for API keys once per session
        def handle_keys(result: dict | None) -> None:
            if not result:
                return
            h1_key = result.get("h1_key")
            bc_key = result.get("bc_key")
            self._do_upload(h1_key, bc_key)
        self.push_screen(PromptScreen(
            "Enter API keys (leave blank to skip that platform)",
            "HackerOne API key,Bugcrowd API key (comma separated)"
        ), handle_keys)

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
            from pathlib import Path
            out_dir = hunts_dir() / self.current_program
            report_path = render_batch_report(self.current_program, vulns, out_dir)
            self.notify(f"report generated: {report_path}")
            # Upload
            from ..bounty_reporter.uploader import upload_report
            # Try both platforms; errors are caught inside uploader
            upload_report(report_path, self.current_program, h1_key, bc_key)
            self.notify("upload completed (check console for details)", severity="information")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"upload failed: {exc}", severity="error")

    def action_delete(self) -> None:
        if not self.current_program:
            return
        name = self.current_program
        if self.registry.remove(name):
            self.registry.save(programs_file())
            self.current_program = None
            self.current_leads = []
            self.refresh_programs()
            self.refresh_leads()
            self.notify(f"deleted program '{name}'", severity="warning")

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

            # Run vuln scan
            vulns = await engine.scan_for_vulns(program, leads)

            # Update view
            if vulns:
                msg = f"[b]scan done[/b] — found {len(vulns)} potential vulnerabilities."
                self.notify(f"found {len(vulns)} potential vulnerabilities", severity="information")
            else:
                msg = "[b]scan done[/b] — no vulnerabilities identified."
                self.notify("scan complete: no vulnerabilities identified", severity="information")
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
