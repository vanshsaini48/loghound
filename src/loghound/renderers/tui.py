from datetime import datetime
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Header, Footer, Static, ListView, ListItem, Label
from textual.binding import Binding
from ..events import Event, Finding
from ..reporting.markdown import generate_markdown_report


class FindingListItem(ListItem):
    """A single finding in the list."""
    
    def __init__(self, finding: Finding):
        self.finding = finding
        label = f"{finding.detection_name}  ({finding.severity.upper()})"
        super().__init__(Label(label))


class DetailsPane(Static):
    """Right-side detail pane. Shows the selected finding."""
    pass


def format_finding(finding: Finding) -> str:
    """Build the detail text for a single finding."""
    entities = ", ".join(f"{k}={v}" for k, v in finding.entities.items())
    evidence = "\n".join(f"  - {line}" for line in finding.evidence)
    return (
        f"{finding.detection_name}  ({finding.severity.upper()})\n"
        f"\n"
        f"Time:      {finding.timestamp}\n"
        f"ATT&CK:    {finding.attack_id or 'N/A'}\n"
        f"Entities:  {entities}\n"
        f"\n"
        f"Description:\n{finding.description}\n"
        f"\n"
        f"Evidence:\n{evidence}\n"
        f"\n"
        f"False-positive notes:\n{finding.false_positive_notes}\n"
    )


def format_pivot(entity_key: str, entity_value: str,
                 related_findings: list[Finding],
                 related_events: list[Event]) -> str:
    """Build the pivot view text for an entity."""
    lines = [
        f"PIVOT: {entity_key} = {entity_value}",
        f"{'=' * 40}",
        "",
        f"Related findings ({len(related_findings)}):",
        "",
    ]
    for f in related_findings:
        lines.append(f"  [{f.severity.upper()}] {f.detection_name} @ {f.timestamp}")
    lines.append("")
    lines.append(f"Related events ({len(related_events)}):")
    lines.append("")
    for ev in related_events:
        lines.append(f"  {ev.raw}")
    return "\n".join(lines)


class TUIApp(App):
    """Two-panel TUI: findings list (left) + detail pane (right)."""
    
    CSS = """
    #findings-list {
        width: 40%;
        border: solid $accent;
    }
    #details-scroll {
        width: 60%;
        border: solid $accent;
    }
    #details {
        padding: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("1", "filter_critical", "Critical", show=True),
        Binding("2", "filter_high", "High", show=True),
        Binding("3", "filter_medium", "Medium", show=True),
        Binding("0", "filter_all", "All", show=True),
        Binding("e", "export", "Export", show=True),
        Binding("p", "pivot", "Pivot", show=True),
    ]
    
    def __init__(self, findings: list[Finding], events: list[Event] | None = None,
                 source_file: str = "", events_count: int = 0):
        super().__init__()
        self.findings = findings
        self.events = events or []
        self.source_file = source_file
        self.events_count = events_count
        self.selected_finding: Finding | None = None
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with ListView(id="findings-list"):
                for finding in self.findings:
                    yield FindingListItem(finding)
            with VerticalScroll(id="details-scroll"):
                yield DetailsPane("Select a finding to view details", id="details")
        yield Footer()
    
    def on_mount(self) -> None:
        severity_counts = {}
        for f in self.findings:
            s = f.severity.upper()
            severity_counts[s] = severity_counts.get(s, 0) + 1
        counts_str = ", ".join(f"{c} {s}" for s, c in severity_counts.items())
        self.sub_title = f"{len(self.findings)} findings ({counts_str}) | {self.events_count} events processed"
        self.query_one(ListView).focus()
    
    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """Fired when the highlighted list item changes (arrow keys)."""
        item = event.item
        if isinstance(item, FindingListItem):
            self.selected_finding = item.finding
            details = self.query_one("#details", DetailsPane)
            details.update(format_finding(item.finding))

    def _rebuild_list(self, severity: str | None = None) -> None:
        """Rebuild the findings list, optionally filtered by severity."""
        list_view = self.query_one("#findings-list", ListView)
        list_view.clear()
        for finding in self.findings:
            if severity is None or finding.severity.upper() == severity:
                list_view.append(FindingListItem(finding))

    def action_filter_critical(self) -> None:
        self._rebuild_list("CRITICAL")

    def action_filter_high(self) -> None:
        self._rebuild_list("HIGH")

    def action_filter_medium(self) -> None:
        self._rebuild_list("MEDIUM")

    def action_filter_all(self) -> None:
        self._rebuild_list(None)

    def action_export(self) -> None:
        """Export findings as a Markdown report."""
        markdown = generate_markdown_report(
            self.findings, self.source_file, self.events_count
        )
        timestamp = datetime.now().isoformat(timespec="seconds").replace(":", "-")
        output_path = Path(f"loghound-report-{timestamp}.md")
        output_path.write_text(markdown)
        details = self.query_one("#details", DetailsPane)
        details.update(f"Report exported to {output_path}")

    def action_pivot(self) -> None:
        """Pivot on the selected finding's entity."""
        if not self.selected_finding:
            return
        details = self.query_one("#details", DetailsPane)
        # Pivot on the first entity (e.g. source_ip or username)
        entities = self.selected_finding.entities
        if not entities:
            details.update("No entities to pivot on.")
            return
        entity_key, entity_value = next(iter(entities.items()))
        # Find related findings
        related_findings = [
            f for f in self.findings
            if entity_value in f.entities.values()
        ]
        # Find related events
        related_events = [
            ev for ev in self.events
            if (ev.source_ip == entity_value or ev.username == entity_value)
        ]
        details.update(format_pivot(
            entity_key, entity_value, related_findings, related_events
        ))


def run_tui(findings: list[Finding], events: list[Event] | None = None,
            source_file: str = "", events_count: int = 0) -> None:
    """Launch the TUI with the given findings."""
    app = TUIApp(findings, events, source_file, events_count)
    app.run()
