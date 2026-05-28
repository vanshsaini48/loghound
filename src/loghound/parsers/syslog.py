import re
from pathlib import Path

PATTERN = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})'  # timestamp
    r'\s+(\S+)'                                           # hostname
    r'\s+(\w+)\[(\d+)\]:'                                # process[pid]
    r'\s+(.+)$'                                           # message
)

def parse_file(file_path: Path):
    skipped = 0
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            match = PATTERN.match(line)
            if match:
                yield {
                    'timestamp': match.group(1),
                    'hostname':  match.group(2),
                    'process':   match.group(3),
                    'pid':       match.group(4),
                    'message':   match.group(5),
                    'raw':       line,
                }
            else:
                skipped += 1
    if skipped:
        print(f'[syslog parser] skipped {skipped} unparseable lines')