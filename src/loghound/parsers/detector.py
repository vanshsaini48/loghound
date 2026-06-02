from pathlib import Path
from . import syslog, apache, jsonlog

PARSERS = [syslog, apache, jsonlog]

def detect_and_parse(file_path: Path):
    """
    Auto-detect log format and parse the file.
    Tries each parser's can_parse() until one matches.
    Returns (parser_name, events_iterator).
    """
    # Read first 50 lines to sample
    sample_lines = []
    with open(file_path) as f:
        for i, line in enumerate(f):
            if i >= 50:
                break
            sample_lines.append(line.strip())
    
    # Try each parser
    for parser in PARSERS:
        if parser.can_parse(sample_lines):
            print(f"[detector] Recognized format: {parser.__name__}")
            return parser.__name__, parser.parse_file(file_path)
    
    # No parser matched
    raise ValueError(f"Could not detect log format in {file_path}")
