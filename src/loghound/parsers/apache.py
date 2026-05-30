import re
from pathlib import Path
from datetime import datetime
from ..events import Event

# Common Log Format: IP - user [timestamp] "METHOD PATH VERSION" status bytes "referer" "user_agent"
PATTERN = re.compile(
    r'^(\S+)'                                          # source IP
    r'\s+\S+\s+\S+'                                    # - -
    r'\s+\[([^\]]+)\]'                                 # [timestamp]
    r'\s+"(\S+)\s+(\S+)\s+(\S+)"'                      # "METHOD PATH VERSION"
    r'\s+(\d+)'                                        # status code
    r'\s+(\d+|-)'                                      # bytes
    r'\s+"([^"]*)"'                                    # referer
    r'\s+"([^"]*)"'                                    # user_agent
)

@staticmethod
def can_parse(sample_lines: list[str]) -> bool:
    """Check if these lines look like Apache Common Log Format."""
    if not sample_lines:
        return False
    return bool(PATTERN.match(sample_lines[0]))

def parse_file(file_path: Path):
    skipped = 0
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            match = PATTERN.match(line)
            if match:
                source_ip = match.group(1)
                timestamp_str = match.group(2)
                http_method = match.group(3)
                http_path = match.group(4)
                http_version = match.group(5)
                http_status = match.group(6)
                http_bytes = match.group(7)
                referer = match.group(8)
                user_agent = match.group(9)
                
                yield Event(
                    timestamp=datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z'),
                    source=str(file_path),
                    event_type='HTTP_REQUEST',
                    source_ip=source_ip,
                    username=None,  # Apache logs don't have a username field
                    raw=line,
                    fields={
                        'http_method': http_method,
                        'http_path': http_path,
                        'http_version': http_version,
                        'http_status': http_status,
                        'http_bytes': http_bytes,
                        'referer': referer,
                        'user_agent': user_agent,
                    }
                )
            else:
                skipped += 1
    if skipped:
        print(f'[apache parser] skipped {skipped} unparseable lines')