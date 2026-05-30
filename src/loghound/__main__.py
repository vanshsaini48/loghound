import sys
import argparse
from datetime import datetime
from pathlib import Path
from .parsers.detector import detect_and_parse
from .engine import run_engine
from .reporting.markdown import generate_markdown_report

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
        "--config",
        type=Path,
        default=Path(__file__).parent.parent.parent / "config" / "default.yaml",
        help="Path to config file (default: config/default.yaml)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Export findings as a Markdown report"
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

    # Detect format and parse events
    try:
        parser_name, events_iter = detect_and_parse(args.log_file)
        events = list(events_iter)
        print(f"Parsed {len(events)} events from {args.log_file}\n")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(2)

    # Run engine
    findings = run_engine(events, config)

    # Output findings
    if args.report:
        # Export as Markdown report
        markdown = generate_markdown_report(
            findings,
            str(args.log_file),
            len(events)
        )

        if args.output:
            output_path = args.output
        else:
            # Generate default filename with timestamp
            timestamp = datetime.now().isoformat(timespec='seconds').replace(":", "-")
            output_path = Path(f"loghound-report-{timestamp}.md")

        output_path.write_text(markdown)
        print(f"Report written to {output_path}")
    else:
        # Print findings to stdout (original behavior)
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

    # Exit codes: 0 if no findings, 1 if findings exist
    sys.exit(0 if not findings else 1)

if __name__ == "__main__":
    main()
