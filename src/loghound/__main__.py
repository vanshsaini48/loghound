import sys
from pathlib import Path
from .parsers.syslog import parse_file
from .engine import run_engine

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m loghound <log_file>")
        sys.exit(2)
    
    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"Error: file not found: {log_path}")
        sys.exit(2)
    
    # Parse events
    events = list(parse_file(log_path))
    print(f"Parsed {len(events)} events from {log_path}\n")
    
    # Default config
    config = {
        "detections": {
            "ssh_brute_force": {"enabled": True, "threshold": 5, "window_minutes": 10},
            "successful_after_brute": {"enabled": True, "threshold": 5, "lookback_minutes": 60},
            "off_hours_login": {"enabled": True, "business_hours": {"start": "08:00", "end": "19:00"}},
        }
    }
    
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
