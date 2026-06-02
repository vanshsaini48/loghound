import sys
import argparse
from datetime import datetime
from pathlib import Path
from .parsers.detector import detect_and_parse
from .engine import run_engine
from .reporting.markdown import generate_markdown_report


class _CountingIterator:
    """Wraps an iterator, counts items yielded."""
    def __init__(self, it):
        self._it = it
        self.count = 0

    def __iter__(self):
        for item in self._it:
            self.count += 1
            yield item


def main():
    parser = argparse.ArgumentParser(
        description="loghound — Security log triage tool"
    )
    parser.add_argument(
        "log_file",
        type=Path,
        help="Path to log file to analyze"
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
        "--report",
        action="store_true",
        help="Export findings as a Markdown report"
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch the interactive terminal UI"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output path for Markdown report (default: loghound-report-<timestamp>.md)"
    )
    args = parser.parse_args()

    # Validate log file
    if not args.log_file.exists():
        print(f"Error: log file not found: {args.log_file}")
        sys.exit(2)

    # Load config
    if not args.config.exists():
        print(f"Error: config file not found: {args.config}")
        sys.exit(2)
    import yaml
    with open(args.config) as f:
        config = yaml.safe_load(f)

    # Validate output directory
    if args.output and not args.output.parent.exists():
        print(f"Error: output directory does not exist: {args.output.parent}")
        sys.exit(2)

    # Determine if progress should be shown (file > 10 MB and not TUI)
    file_size_mb = args.log_file.stat().st_size / (1024 * 1024)
    show_progress = file_size_mb > 10 and not args.tui

    # Detect format and parse
    try:
        parser_name, events_iter = detect_and_parse(
            args.log_file, format_override=args.format, show_progress=show_progress
        )
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(2)

    if args.tui:
        # TUI needs the full event list for pivot and raw-event display
        events = list(events_iter)
        event_count = len(events)
        findings = run_engine(iter(events), config)
    else:
        # Streaming: events are never fully materialized
        counter = _CountingIterator(events_iter)
        findings = run_engine(counter, config)
        event_count = counter.count

    print(f"Parsed {event_count} events from {args.log_file}\n")

    # Output
    if args.report:
        markdown = generate_markdown_report(
            findings, str(args.log_file), event_count
        )
        if args.output:
            output_path = args.output
        else:
            timestamp = datetime.now().isoformat(
                timespec='seconds'
            ).replace(":", "-")
            output_path = Path(f"loghound-report-{timestamp}.md")
        output_path.write_text(markdown)
        print(f"Report written to {output_path}")
    elif args.tui:
        from .renderers.tui import run_tui
        run_tui(findings, events, str(args.log_file), event_count)
    else:
        if not findings:
            print("No findings.")
        else:
            print(f"Found {len(findings)} finding(s):\n")
            for i, finding in enumerate(findings, 1):
                print(f"{i}. [{finding.severity.upper()}] {finding.detection_name}")
                print(f"   Time: {finding.timestamp}")
                print(f"   Entities: {finding.entities}")
                print(f"   Description: {finding.description}")
                print()

    sys.exit(0 if not findings else 1)


if __name__ == "__main__":
    main()
