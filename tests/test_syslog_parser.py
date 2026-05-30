from pathlib import Path
from loghound.parsers.syslog import parse_file
from loghound.events import Event
from datetime import datetime

FIXTURE = Path('tests/fixtures/sample_auth.log')

def test_parse_returns_events():
    events = list(parse_file(FIXTURE))
    assert len(events) == 24

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
def test_extracts_source_ip_and_username():
    tmp = Path('tests/fixtures/auth_lines.log')
    tmp.write_text(
        "Mar 15 14:31:02 ubuntu-server sshd[19102]: Failed password for root from 203.0.113.42 port 44521 ssh2\n"
        "Mar 15 14:31:11 ubuntu-server sshd[19105]: Failed password for invalid user admin from 203.0.113.42 port 44542 ssh2\n"
    )
    events = list(parse_file(tmp))

    # plain username shape
    assert events[0].source_ip == '203.0.113.42'
    assert events[0].username == 'root'

    # 'invalid user' shape -> username is the real account, not the word 'invalid'
    assert events[1].source_ip == '203.0.113.42'
    assert events[1].username == 'admin'

    tmp.unlink()