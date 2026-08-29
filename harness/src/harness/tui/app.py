"""The security-harness TUI: pick a program, run recon, browse ranked leads,
scaffold a report — all menu/key driven, no commands to memorize."""
from __future__ import annotations

from pathlib import Path

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


class SearchScreen(ModalScreen[str | None]):
    """Modal to enter a CVE search query."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Search cve-index", id="dialog-title")
            yield Input(placeholder="e.g. nginx 1.18 path traversal", id="q")
            with Horizontal(id="dialog-buttons"):
                yield Button("Search", variant="primary", id="go")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
        else:
            self.dismiss(self.query_one("#q", Input).value.strip() or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class HarnessApp(App[None]):
    CSS_PATH = "app.tcss"
    TITLE = "security-harness"
    BINDINGS = [
        Binding("r", "recon", "Recon"),
        Binding("s", "search", "Search CVEs"),
        Binding("w", "report", "Write report"),
        Binding("a", "add", "Add program"),
        Binding("d", "delete", "Delete program"),
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
            "[b]r[/b] recon · [b]w[/b] scaffold report on the highlighted lead."
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

    def action_recon(self) -> None:
        if not self.current_program:
            self.notify("no program selected", severity="warning")
            return
        program = self.registry.get(self.current_program)
        runnable, why = program.is_runnable()
        if not runnable:
            self.notify(f"can't run: {why}", severity="error")
            return
        self._run_recon(program)

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

    def action_search(self) -> None:
        program = self.registry.get(self.current_program) if self.current_program else None
        cve_url = (program.cve_index_url if program else None) or "http://localhost:8080"

        def handle(query: str | None) -> None:
            if query:
                self._run_search(query, cve_url)

        self.push_screen(SearchScreen(), handle)

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
        table = self.query_one("#leads", DataTable)
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            index = int(row_key.value)
        except Exception:  # noqa: BLE001
            index = 0
        lead = self.current_leads[index]
        template = finding_template(self.current_program, lead)
        out_dir = hunts_dir() / self.current_program
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_host = lead.get("host", "lead").replace("/", "_")
        path = out_dir / f"finding-{safe_host}.yaml"
        Path(path).write_text(template, encoding="utf-8")
        self.query_one("#detail", Static).update(
            f"[b]scaffold written:[/b] {path}\n"
            "Fill the TODOs from your manual testing, then:\n"
            f"  bounty-reporter render {path} --out ./out"
        )
        self.notify(f"report scaffold → {path}")


def main() -> None:
    HarnessApp().run()


if __name__ == "__main__":
    main()
