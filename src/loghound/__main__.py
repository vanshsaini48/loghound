import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path
from .parsers.detector import detect_and_parse
from .parsers.merge import merge_event_streams
from .engine import run_engine
from .triage import run_triage
from .reporting.markdown import generate_markdown_report
from .reporting.json_report import generate_json_report


class _CountingIterator:
    """Wraps an iterator, counts items yielded."""
    def __init__(self, it):
        self._it = it
        self.count = 0

    def __iter__(self):
        for item in self._it:
            self.count += 1
            yield item


def _filter_by_time(events_iter, since_str, until_str):
    """Filter events to a time window. Yields only events within [since, until)."""
    since_dt = None
    until_dt = None
    
    if since_str:
        try:
            since_dt = datetime.fromisoformat(since_str)
            # If naive, assume UTC
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise ValueError(f"Invalid --since format: {since_str}. Use ISO 8601 (e.g., 2026-06-01T00:00:00)")
    
    if until_str:
        try:
            until_dt = datetime.fromisoformat(until_str)
            # If naive, assume UTC
            if until_dt.tzinfo is None:
                until_dt = until_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise ValueError(f"Invalid --until format: {until_str}. Use ISO 8601 (e.g., 2026-06-02T23:59:59)")
    
    for event in events_iter:
        if since_dt and event.timestamp < since_dt:
            continue
        if until_dt and event.timestamp >= until_dt:
            continue
        yield event


def main():
    parser = argparse.ArgumentParser(
        description="loghound — Security log triage tool"
    )
    parser.add_argument(
        "log_files",
        type=Path,
        nargs='+',
        help="Log file(s) to analyze (supports glob patterns, e.g., auth.log*)"
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["syslog", "apache", "nginx", "json"],
        default=None,
        help="Override auto-detection with a specific log format"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).parent / "default_config.yaml",
        help="Path to config file (default: config/default.yaml)"
    )
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        help="Only process events at or after this timestamp (ISO 8601 format, e.g., 2026-06-01T00:00:00)"
    )
    parser.add_argument(
        "--until",
        type=str,
        default=None,
        help="Only process events before this timestamp (ISO 8601 format, e.g., 2026-06-02T23:59:59)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Export findings as a Markdown report"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Export findings as JSON-lines (one object per line)"
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch the interactive terminal UI"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output path for report (default: loghound-report-<timestamp>.md or .jsonl)"
    )
    args = parser.parse_args()

    # Expand globs and validate files exist
    expanded_files = []
    for pattern in args.log_files:
        if '*' in str(pattern) or '?' in str(pattern):
            # Glob pattern
            matches = list(Path('.').glob(str(pattern)))
            if not matches:
                print(f"Error: no files match pattern: {pattern}")
                sys.exit(2)
            expanded_files.extend(sorted(matches))
        else:
            # Single file
            if not pattern.exists():
                print(f"Error: log file not found: {pattern}")
                sys.exit(2)
            expanded_files.append(pattern)

    if not args.config.exists():
        print(f"Error: config file not found: {args.config}")
        sys.exit(2)
    
    import yaml
    with open(args.config) as f:
        config = yaml.safe_load(f)

    if args.output and not args.output.parent.exists():
        print(f"Error: output directory does not exist: {args.output.parent}")
        sys.exit(2)

    # Determine if we should show progress
    total_size_mb = sum(f.stat().st_size for f in expanded_files) / (1024 * 1024)
    show_progress = total_size_mb > 10 and not args.tui

    # Parse and merge events from all files
    try:
        events_iter = merge_event_streams(
            expanded_files, 
            format_override=args.format, 
            show_progress=show_progress
        )
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(2)

    # Apply time filtering
    try:
        events_iter = _filter_by_time(events_iter, args.since, args.until)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(2)

    if args.tui:
        events = list(events_iter)
        event_count = len(events)
        findings = run_engine(iter(events), config)
        scored_findings = run_triage(findings, config)
    else:
        counter = _CountingIterator(events_iter)
        findings = run_engine(counter, config)
        event_count = counter.count
        scored_findings = run_triage(findings, config)

    print(f"Parsed {event_count} events from {len(expanded_files)} file(s)\n")

    if args.report:
        markdown = generate_markdown_report(
            scored_findings, str(expanded_files[0]), event_count
        )
        if args.output:
            output_path = args.output
        else:
            timestamp = datetime.now().isoformat(
                timespec='seconds'
            ).replace(":", "-")
            output_path = Path(f"loghound-report-{timestamp}.md")
        output_path.write_text(markdown)
        print(f"Markdown report written to {output_path}")
    elif args.json:
        json_output = generate_json_report(
            scored_findings, str(expanded_files[0]), event_count
        )
        if args.output:
            output_path = args.output
        else:
            timestamp = datetime.now().isoformat(
                timespec='seconds'
            ).replace(":", "-")
            output_path = Path(f"loghound-report-{timestamp}.jsonl")
        output_path.write_text(json_output)
        print(f"JSON report written to {output_path}")
    elif args.tui:
        from .renderers.tui import run_tui
        run_tui(scored_findings, events, str(expanded_files[0]), event_count)
    else:
        active = [sf for sf in scored_findings if not sf.suppressed]
        if not active:
            suppressed_count = len([sf for sf in scored_findings if sf.suppressed])
            msg = "No active findings."
            if suppressed_count:
                msg += f" ({suppressed_count} suppressed by allowlist)"
            print(msg)
        else:
            print(f"Found {len(active)} active finding(s):\n")
            for i, sf in enumerate(active, 1):
                print(f"{i}. [{sf.finding.severity.upper()}] {sf.finding.detection_name}")
                print(f"   Time: {sf.finding.timestamp}")
                print(f"   Entities: {sf.finding.entities}")
                if sf.count > 1:
                    print(f"   Occurrences: {sf.count}")
                print(f"   Risk: {sum(sf.entity_risk.values())}")
                print(f"   Description: {sf.finding.description}")
                if sf.suppression_reason:
                    print(f"   Suppression: {sf.suppression_reason}")
                print()

    sys.exit(0 if not [sf for sf in scored_findings if not sf.suppressed] else 1)


if __name__ == "__main__":
    main()
