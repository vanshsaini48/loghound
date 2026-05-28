from pathlib import Path
from src.loghound.parsers.syslog import parse_file
from src.loghound.events import Event
from datetime import datetime

FIXTURE = Path('tests/fixtures/sample_auth.log')

def test_parse_returns_events():
    events = list(parse_file(FIXTURE))
    assert len(events) == 20

def test_event_is_correct_type():
    events = list(parse_file(FIXTURE))
    assert isinstance(events[0], Event)

def test_timestamp_is_datetime():
    events = list(parse_file(FIXTURE))
    assert isinstance(events[0].timestamp, datetime)

def test_garbage_line_is_skipped():
    tmp = Path('tests/fixtures/garbage.log')
    tmp.write_text("this is not a valid syslog line\n")
    events = list(parse_file(tmp))
    assert len(events) == 0
    tmp.unlink()