from pathlib import Path
from . import syslog, apache, nginx, jsonlog
from .reader import smart_open

PARSERS = [syslog, apache, nginx, jsonlog]
FORMAT_MAP = {
    'syslog': syslog,
    'apache': apache,
    'nginx': nginx,
    'json': jsonlog,
    'jsonlog': jsonlog,
}

def detect_and_parse(file_path: Path, format_override: str = None, show_progress: bool = False):
    """
    Auto-detect log format and parse the file.
    Tries each parser's can_parse() until one matches.
    Returns (parser_name, events_iterator).
    """
    if format_override:
        parser = FORMAT_MAP.get(format_override)
        if parser is None:
            raise ValueError(f"Unknown format: {format_override}. Valid formats: {', '.join(sorted(FORMAT_MAP))}")
        print(f"[detector] Using format override: {format_override}")
        return format_override, parser.parse_file(file_path, show_progress=show_progress)
    
    # Read first 50 lines to sample (use smart_open for gzip support)
    sample_lines = []
    with smart_open(file_path) as f:
        for i, line in enumerate(f):
            if i >= 50:
                break
            sample_lines.append(line.strip())
    
    # Try each parser
    for parser in PARSERS:
        if parser.can_parse(sample_lines):
            print(f"[detector] Recognized format: {parser.__name__}")
            return parser.__name__, parser.parse_file(file_path, show_progress=show_progress)
    
    # No parser matched
    raise ValueError(f"Could not detect log format in {file_path}")
