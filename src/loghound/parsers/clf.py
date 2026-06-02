import re
from pathlib import Path
from datetime import datetime, timezone
from ..events import Event
from .reader import smart_open

# Combined Log Format — shared by Apache and Nginx default configs
CLF_PATTERN = re.compile(
    r'^(\S+)'                                          # source IP
    r'\s+\S+\s+\S+'                                    # ident, auth
    r'\s+\[([^\]]+)\]'                                 # [timestamp]
    r'\s+"(\S+)\s+(\S+)\s+(\S+)"'                      # "METHOD PATH VERSION"
    r'\s+(\d+)'                                        # status code
    r'\s+(\d+|-)'                                      # bytes
    r'\s+"([^"]*)"'                                    # referer
    r'\s+"([^"]*)"'                                    # user_agent
)


def clf_can_parse(sample_lines: list[str]) -> bool:
    if not sample_lines:
        return False
    return bool(CLF_PATTERN.match(sample_lines[0]))


def clf_parse_file(file_path: Path, parser_label: str = 'clf'):
    skipped = 0
    with smart_open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = CLF_PATTERN.match(line)
            if match:
                yield Event(
                    timestamp=datetime.strptime(match.group(2), '%d/%b/%Y:%H:%M:%S %z').astimezone(timezone.utc),
                    source=str(file_path),
                    event_type='HTTP_REQUEST',
                    source_ip=match.group(1),
                    username=None,
                    raw=line,
                    fields={
                        'http_method': match.group(3),
                        'http_path': match.group(4),
                        'http_version': match.group(5),
                        'http_status': match.group(6),
                        'http_bytes': match.group(7),
                        'referer': match.group(8),
                        'user_agent': match.group(9),
                    }
                )
            else:
                skipped += 1
    if skipped:
        print(f'[{parser_label} parser] skipped {skipped} unparseable lines')
