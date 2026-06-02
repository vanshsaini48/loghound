from datetime import datetime
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Header, Footer, Static, ListView, ListItem, Label
from textual.binding import Binding
from ..events import Event, Finding
from ..triage.models import ScoredFinding
from ..reporting.markdown import generate_markdown_report


class FindingListItem(ListItem):
    """A single finding in the list."""

    def __init__(self, finding: ScoredFinding):
        self.finding = finding
        f = finding.finding

        risk_score = sum(finding.entity_risk.values())

        label = (
            f"[{risk_score:>3}] "
            f"{f.detection_name} "
            f"({f.severity.upper()})"
        )

        super().__init__(Label(label))


class DetailsPane(Static):
    """Right-side detail pane. Shows the selected finding."""
    pass


class SummaryPane(Static):
    """Top summary dashboard."""
    pass




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

    for ev in related_events:
        lines.append(f"  {ev.raw}")

    return "\n".join(lines)



def build_summary(findings: list[ScoredFinding], events_count: int) -> str:
    """Build dashboard summary text."""

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    entity_risk = {}

    for sf in findings:
        sev = sf.finding.severity.upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for entity, risk in sf.entity_risk.items():
            entity_risk[entity] = entity_risk.get(entity, 0) + risk

    top_entities = sorted(
        entity_risk.items(),
        key=lambda x: x[1],
        reverse=True,
    )[:5]

    lines = [
        f"Events Processed: {events_count}",
        f"Findings: {len(findings)}",
        "",
        "Top Risk Entities:",
    ]

    if top_entities:
        for entity, risk in top_entities:
            lines.append(f"  {entity}: {risk}")
    else:
        lines.append("  None")

    lines.extend([
        "",
        "Severity Counts:",
        f"  CRITICAL: {severity_counts['CRITICAL']}",
        f"  HIGH: {severity_counts['HIGH']}",
        f"  MEDIUM: {severity_counts['MEDIUM']}",
        f"  LOW: {severity_counts['LOW']}",
    ])

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
    #summary {
        height: 18;
        border: solid $accent;
        padding: 1;
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
    
    def __init__(self, findings: list[ScoredFinding], events: list[Event] | None = None,
                 source_file: str = "", events_count: int = 0):
        super().__init__()
        self.findings = sorted(
            findings,
            key=lambda sf: (
                -sum(sf.entity_risk.values()),
                sf.finding.detection_name,
            ),
        )
        self.events = events or []
        self.source_file = source_file
        self.events_count = events_count
        self.selected_finding: ScoredFinding | None = None
    
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
                yield DetailsPane(
                    "Select a finding to view details",
                    id="details",
                )

        yield Footer()
    
    def on_mount(self) -> None:
        severity_counts = {}
        for f in self.findings:
            s = f.finding.severity.upper()
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
            if severity is None or finding.finding.severity.upper() == severity:
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
        entities = self.selected_finding.finding.entities
        if not entities:
            details.update("No entities to pivot on.")
            return
        entity_key, entity_value = next(iter(entities.items()))
        # Find related findings
        related_findings = [
            f for f in self.findings
            if entity_value in f.finding.entities.values()
        ]
        # Find related events
        related_events = [
            ev for ev in self.events
            if (ev.source_ip == entity_value or ev.username == entity_value)
        ]
        details.update(format_pivot(
            entity_key, entity_value, related_findings, related_events
        ))


def run_tui(findings: list[ScoredFinding], events: list[Event] | None = None,
            source_file: str = "", events_count: int = 0) -> None:
    """Launch the TUI with the given findings."""
    app = TUIApp(findings, events, source_file, events_count)
    app.run()
