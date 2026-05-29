import re
from pathlib import Path
from dateutil import parser as dateutil_parser
from src.loghound.events import Event

PATTERN = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})'  # timestamp
    r'\s+(\S+)'                                           # hostname
    r'\s+(\w+)\[(\d+)\]:'                                # process[pid]
    r'\s+(.+)$'                                           # message
)

AUTH_PATTERN = re.compile(r'for (?:invalid user )?(\S+) from (\S+)')  # -> username, source_ip


def parse_file(file_path: Path):
    skipped = 0
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            match = PATTERN.match(line)
            if match:
                message = match.group(5)
                auth = AUTH_PATTERN.search(message)
                username = auth.group(1) if auth else None
                source_ip = auth.group(2) if auth else None
                yield Event(
                    timestamp=dateutil_parser.parse(match.group(1)),
                    source=str(file_path),
                    event_type='syslog',
                    source_ip=source_ip,
                    username=username,
                    raw=line,
                    fields={
                        'hostname': match.group(2),
                        'process':  match.group(3),
                        'pid':      match.group(4),
                        'message':  message,
                    }
                )
            else:
                skipped += 1
    if skipped:
        print(f'[syslog parser] skipped {skipped} unparseable lines')