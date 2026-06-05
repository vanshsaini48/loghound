from datetime import datetime
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Header, Footer, Static, ListView, ListItem, Label, Input
from textual.binding import Binding
from textual.screen import ModalScreen
from ..events import Event, Finding
from ..triage.models import ScoredFinding
from ..reporting.markdown import generate_markdown_report


class FindingListItem(ListItem):
    """A single finding in the list."""

    def __init__(self, finding: ScoredFinding):
        self.finding = finding
        f = finding.finding
        risk_score = sum(finding.entity_risk.values())
        count_str = f" x{finding.count}" if finding.count > 1 else ""
        label = (
            f"[{risk_score:>3}] "
            f"{f.severity.upper():<8} "
            f"{f.detection_name}"
            f"{count_str}"
        )
        super().__init__(Label(label))


class DetailsPane(Static):
    """Right-side detail pane."""
    pass


class SummaryPane(Static):
    """Top summary dashboard."""
    pass


class HelpScreen(ModalScreen):
    """Help overlay showing keybindings."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("question_mark", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        yield Static(
            "LogHound — Keyboard Shortcuts\n"
            "═══════════════════════════════\n"
            "\n"
            "  ↑/↓       Navigate findings\n"
            "  /         Search / filter findings\n"
            "  Escape    Clear search\n"
            "  1         Show CRITICAL only\n"
            "  2         Show HIGH only\n"
            "  3         Show MEDIUM only\n"
            "  0         Show ALL findings\n"
            "  s         Cycle sort: risk → time → severity\n"
            "  p         Pivot on selected entity\n"
            "  e         Export Markdown report\n"
            "  ?         This help screen\n"
            "  q         Quit\n"
            "\n"
            "Press Escape to close.",
            id="help-text",
        )

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-text {
        width: 50;
        height: 22;
        padding: 1 2;
        border: thick $accent;
        background: $surface;
    }
    """


def _sparkline(findings: list[ScoredFinding], width: int = 24) -> str:
    """Build a simple text sparkline of finding activity over time."""
    if not findings:
        return ""

    timestamps = [sf.finding.timestamp for sf in findings]
    t_min = min(timestamps)
    t_max = max(timestamps)
    span = (t_max - t_min).total_seconds()

    if span == 0:
        return "▇" * min(len(findings), width)

    buckets = [0] * width
    for ts in timestamps:
        idx = int(((ts - t_min).total_seconds() / span) * (width - 1))
        buckets[idx] += 1

    max_val = max(buckets) or 1
    blocks = " ▁▂▃▄▅▆▇"
    return "".join(blocks[min(int(b / max_val * 7), 7)] for b in buckets)


def format_finding(finding: ScoredFinding) -> str:
    """Build the detail text for a single finding."""
    f = finding.finding
    entities = ", ".join(f"{k}={v}" for k, v in f.entities.items())
    evidence = "\n".join(f"  - {line}" for line in f.evidence)
    risk_score = sum(finding.entity_risk.values())
    ioc_hits = ", ".join(finding.ioc_hits) if finding.ioc_hits else "None"

    return (
        f"{f.detection_name}  ({f.severity.upper()})\n"
        f"\n"
        f"Time:         {f.timestamp}\n"
        f"ATT&CK:       {f.attack_id or 'N/A'}\n"
        f"Entities:     {entities}\n"
        f"Risk Score:   {risk_score}\n"
        f"Occurrences:  {finding.count}\n"
        f"IOC Hits:     {ioc_hits}\n"
        f"Suppressed:   {'Yes' if finding.suppressed else 'No'}\n"
        f"\n"
        f"Description:\n{f.description}\n"
        f"\n"
        f"Evidence:\n{evidence}\n"
        f"\n"
        f"False-positive notes:\n{f.false_positive_notes}\n"
    )


def format_pivot(
    entity_key: str,
    entity_value: str,
    related_findings: list[ScoredFinding],
    related_events: list[Event],
) -> str:
    """Build the pivot view text for an entity."""
    lines = [
        f"PIVOT: {entity_key} = {entity_value}",
        f"{'=' * 40}",
        "",
        f"Related findings ({len(related_findings)}):",
        "",
    ]
    for sf in related_findings:
        f = sf.finding
        lines.append(
            f"  [{f.severity.upper()}] {f.detection_name} @ {f.timestamp}"
        )
    lines.append("")
    lines.append(f"Related events ({len(related_events)}):")
    lines.append("")
    for ev in related_events[:50]:  # Cap to avoid flooding
        lines.append(f"  {ev.raw}")
    if len(related_events) > 50:
        lines.append(f"  ... and {len(related_events) - 50} more")
    return "\n".join(lines)


def build_summary(findings: list[ScoredFinding], events_count: int) -> str:
    """Build dashboard summary text."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    entity_risk = {}
    active = [sf for sf in findings if not sf.suppressed]
    suppressed = len(findings) - len(active)

    for sf in active:
        sev = sf.finding.severity.upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for entity, risk in sf.entity_risk.items():
            entity_risk[entity] = entity_risk.get(entity, 0) + risk

    top_entities = sorted(entity_risk.items(), key=lambda x: x[1], reverse=True)[:5]
    sparkline = _sparkline(active)

    lines = [
        f"Events: {events_count}  |  Findings: {len(active)}  |  Suppressed: {suppressed}",
        "",
        f"Activity: {sparkline}",
        "",
        "Severity:",
        f"  CRITICAL: {severity_counts['CRITICAL']}  HIGH: {severity_counts['HIGH']}  MEDIUM: {severity_counts['MEDIUM']}  LOW: {severity_counts['LOW']}",
        "",
        "Top Risk Entities:",
    ]
    if top_entities:
        for entity, risk in top_entities:
            lines.append(f"  {entity}: {risk}")
    else:
        lines.append("  None")

    return "\n".join(lines)


class TUIApp(App):
    """Dashboard TUI: summary, findings list, detail pane, live search."""

    CSS = """
    #findings-list {
        width: 40%;
        border: solid $accent;
    }
    #details-scroll {
        width: 60%;
        border: solid $accent;
    }
    #summary {
        height: 14;
        border: solid $accent;
        padding: 1;
    }
    #details {
        padding: 1;
    }
    #search-bar {
        dock: bottom;
        height: 3;
        display: none;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("1", "filter_critical", "Critical", show=True),
        Binding("2", "filter_high", "High", show=True),
        Binding("3", "filter_medium", "Medium", show=True),
        Binding("0", "filter_all", "All", show=True),
        Binding("slash", "search", "Search", show=True),
        Binding("s", "sort_cycle", "Sort", show=True),
        Binding("e", "export", "Export", show=True),
        Binding("p", "pivot", "Pivot", show=True),
        Binding("question_mark", "help", "Help", show=True),
        Binding("escape", "clear_search", "Clear", show=False),
    ]

    def __init__(self, findings: list[ScoredFinding], events: list[Event] | None = None,
                 source_file: str = "", events_count: int = 0):
        super().__init__()
        self.all_findings = findings
        self.findings = sorted(
            findings,
            key=lambda sf: (-sum(sf.entity_risk.values()), sf.finding.detection_name),
        )
        self.events = events or []
        self.source_file = source_file
        self.events_count = events_count
        self.selected_finding: ScoredFinding | None = None
        self._sort_mode = "risk"  # risk, time, severity
        self._search_query = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield SummaryPane(
            build_summary(self.findings, self.events_count),
            id="summary",
        )
        with Horizontal():
            with ListView(id="findings-list"):
                for finding in self.findings:
                    yield FindingListItem(finding)
            with VerticalScroll(id="details-scroll"):
                yield DetailsPane("Select a finding to view details", id="details")
        yield Input(placeholder="Search findings...", id="search-bar")
        yield Footer()

    def on_mount(self) -> None:
        severity_counts = {}
        for f in self.findings:
            s = f.finding.severity.upper()
            severity_counts[s] = severity_counts.get(s, 0) + 1
        counts_str = ", ".join(f"{c} {s}" for s, c in severity_counts.items())
        self.sub_title = f"{len(self.findings)} findings ({counts_str}) | {self.events_count} events"
        self.query_one(ListView).focus()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        item = event.item
        if isinstance(item, FindingListItem):
            self.selected_finding = item.finding
            details = self.query_one("#details", DetailsPane)
            details.update(format_finding(item.finding))

    def _rebuild_list(self, severity: str | None = None) -> None:
        """Rebuild findings list with optional severity filter and search."""
        list_view = self.query_one("#findings-list", ListView)
        list_view.clear()
        for finding in self.findings:
            if severity and finding.finding.severity.upper() != severity:
                continue
            if self._search_query:
                searchable = (
                    finding.finding.detection_name
                    + " " + finding.finding.description
                    + " " + str(finding.finding.entities)
                ).lower()
                if self._search_query.lower() not in searchable:
                    continue
            list_view.append(FindingListItem(finding))

    def _sort_findings(self) -> None:
        """Sort findings by current sort mode."""
        if self._sort_mode == "risk":
            self.findings = sorted(
                self.findings,
                key=lambda sf: (-sum(sf.entity_risk.values()), sf.finding.detection_name),
            )
        elif self._sort_mode == "time":
            self.findings = sorted(
                self.findings,
                key=lambda sf: sf.finding.timestamp,
            )
        elif self._sort_mode == "severity":
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            self.findings = sorted(
                self.findings,
                key=lambda sf: sev_rank.get(sf.finding.severity, 9),
            )

    def action_filter_critical(self) -> None:
        self._rebuild_list("CRITICAL")

    def action_filter_high(self) -> None:
        self._rebuild_list("HIGH")

    def action_filter_medium(self) -> None:
        self._rebuild_list("MEDIUM")

    def action_filter_all(self) -> None:
        self._search_query = ""
        self._rebuild_list(None)

    def action_search(self) -> None:
        """Show search bar and focus it."""
        search_bar = self.query_one("#search-bar", Input)
        search_bar.styles.display = "block"
        search_bar.focus()

    def action_clear_search(self) -> None:
        """Clear search and hide bar."""
        search_bar = self.query_one("#search-bar", Input)
        search_bar.value = ""
        search_bar.styles.display = "none"
        self._search_query = ""
        self._rebuild_list(None)
        self.query_one(ListView).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Live search as user types."""
        if event.input.id == "search-bar":
            self._search_query = event.value
            self._rebuild_list(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """When Enter is pressed in search, focus back to list."""
        if event.input.id == "search-bar":
            self.query_one(ListView).focus()

    def action_sort_cycle(self) -> None:
        """Cycle sort mode: risk -> time -> severity -> risk."""
        cycle = {"risk": "time", "time": "severity", "severity": "risk"}
        self._sort_mode = cycle[self._sort_mode]
        self._sort_findings()
        self._rebuild_list(None)
        details = self.query_one("#details", DetailsPane)
        details.update(f"Sorted by: {self._sort_mode}")

    def action_export(self) -> None:
        markdown = generate_markdown_report(
            self.findings, self.source_file, self.events_count
        )
        timestamp = datetime.now().isoformat(timespec="seconds").replace(":", "-")
        output_path = Path(f"loghound-report-{timestamp}.md")
        output_path.write_text(markdown)
        details = self.query_one("#details", DetailsPane)
        details.update(f"Report exported to {output_path}")

    def action_pivot(self) -> None:
        if not self.selected_finding:
            return
        details = self.query_one("#details", DetailsPane)
        entities = self.selected_finding.finding.entities
        if not entities:
            details.update("No entities to pivot on.")
            return
        entity_key, entity_value = next(iter(entities.items()))
        related_findings = [
            f for f in self.findings
            if entity_value in f.finding.entities.values()
        ]
        related_events = [
            ev for ev in self.events
            if (ev.source_ip == entity_value or ev.username == entity_value)
        ]
        details.update(format_pivot(
            entity_key, entity_value, related_findings, related_events
        ))

    def action_help(self) -> None:
        """Show help overlay."""
        self.push_screen(HelpScreen())


def run_tui(findings: list[ScoredFinding], events: list[Event] | None = None,
            source_file: str = "", events_count: int = 0) -> None:
    """Launch the TUI with the given findings."""
    app = TUIApp(findings, events, source_file, events_count)
    app.run()
