import re
from pathlib import Path
from dateutil import parser as dateutil_parser
from ..events import Event

PATTERN = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})'  # timestamp
    r'\s+(\S+)'                                           # hostname
    r'\s+(\w+)(?:\[(\d+)\])?:'                           # process[optional pid]
    r'\s+(.+)$'                                           # message
)

AUTH_PATTERN = re.compile(r'for (?:invalid user )?(\S+) from (\S+)')

@staticmethod
def can_parse(sample_lines: list[str]) -> bool:
    """Check if these lines look like syslog (auth.log)."""
    if not sample_lines:
        return False
    return bool(PATTERN.match(sample_lines[0]))

def _detect_event_type(process: str, message: str) -> str:
    """Detect specific event type for sudo events."""
    if process == "sudo":
        msg_lower = message.lower()
        if "command=" in msg_lower or "session opened" in msg_lower:
            return "SUDO_SUCCESS"
        elif any(keyword in msg_lower for keyword in ["denied", "incorrect", "authentication failure", "sorry"]):
            return "SUDO_FAILURE"
    return "syslog"

def parse_file(file_path: Path):
    skipped = 0
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            match = PATTERN.match(line)
            if match:
                process = match.group(3)
                pid = match.group(4)
                message = match.group(5)
                auth = AUTH_PATTERN.search(message)
                username = auth.group(1) if auth else None
                source_ip = auth.group(2) if auth else None
                event_type = _detect_event_type(process, message)
                yield Event(
                    timestamp=dateutil_parser.parse(match.group(1)),
                    source=str(file_path),
                    event_type=event_type,
                    source_ip=source_ip,
                    username=username,
                    raw=line,
                    fields={
                        'hostname': match.group(2),
                        'process':  process,
                        'pid':      pid,
                        'message':  message,
                    }
                )
            else:
                skipped += 1
    if skipped:
        print(f'[syslog parser] skipped {skipped} unparseable lines')
