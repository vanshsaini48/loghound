import sys
import argparse
import yaml
from pathlib import Path
from .parsers.syslog import parse_file
from .engine import run_engine

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
    
    args = parser.parse_args()
    
    # Validate log file
    if not args.log_file.exists():
        print(f"Error: log file not found: {args.log_file}")
        sys.exit(2)
    
    # Load config
    if not args.config.exists():
        print(f"Error: config file not found: {args.config}")
        sys.exit(2)
    
    with open(args.config) as f:
        config = yaml.safe_load(f)
    
    # Parse events
    events = list(parse_file(args.log_file))
    print(f"Parsed {len(events)} events from {args.log_file}\n")
    
    # Run engine
    findings = run_engine(events, config)
    
    # Output findings
    if not findings:
        print("No findings.")
        sys.exit(0)
    
    print(f"Found {len(findings)} finding(s):\n")
    for i, finding in enumerate(findings, 1):
        print(f"{i}. [{finding.severity.upper()}] {finding.detection_name}")
        print(f"   Time: {finding.timestamp}")
        print(f"   Entities: {finding.entities}")
        print(f"   Description: {finding.description}")
        print()
    
    sys.exit(1)

if __name__ == "__main__":
    main()
