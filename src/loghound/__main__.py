import sys
from pathlib import Path
from src.loghound.parsers.syslog import parse_file

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m loghound <log_file>")
        sys.exit(2)

    log_path = Path(sys.argv[1])

    if not log_path.exists():
        print(f"Error: file not found: {log_path}")
        sys.exit(2)

    events = list(parse_file(log_path))
    print(f"Parsed {len(events)} events from {log_path}")

if __name__ == "__main__":
    main()
