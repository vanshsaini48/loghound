import re
from pathlib import Path
from datetime import timezone
from dateutil import parser as dateutil_parser
from ..events import Event
from .reader import smart_open
PATTERN = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})'  # timestamp
    r'\s+(\S+)'                                           # hostname
    r'\s+(\w+)(?:\[(\d+)\])?:'                           # process[optional pid]
    r'\s+(.+)$'                                           # message
)
AUTH_PATTERN = re.compile(r'for (?:invalid user )?(\S+) from (\S+)')
SUDO_CMD_PATTERN = re.compile(r'^(\S+)\s+:\s+TTY=')                                 # "jdoe : TTY=..."
SUDO_PAM_PATTERN = re.compile(r'session opened for user \S+ by (\S+?)(?:\(|\s|$)')  # "...by jdoe(uid=1000)"
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
def _extract_sudo_user(message: str) -> str | None:
    """Extract the invoking user from a sudo log line.

    Handles both formats found in auth.log:
      "jdoe : TTY=pts/0 ; ... COMMAND=..."                                     -> jdoe
      "pam_unix(sudo:session): session opened for user root by jdoe(uid=1000)" -> jdoe

    Note: in the pam format we deliberately capture the user after 'by'
    (the human running sudo), NOT the 'for user <x>' target.
    """
    m = SUDO_CMD_PATTERN.match(message)
    if m:
        return m.group(1)
    m = SUDO_PAM_PATTERN.search(message)
    if m:
        return m.group(1)
    return None
def parse_file(file_path: Path, show_progress: bool = False):
    skipped = 0
    with smart_open(file_path, show_progress=show_progress) as f:
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
                if process == "sudo" and username is None:
                    username = _extract_sudo_user(message)
                yield Event(
                    timestamp=dateutil_parser.parse(match.group(1)).replace(tzinfo=timezone.utc),
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
