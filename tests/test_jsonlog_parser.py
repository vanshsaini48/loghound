from datetime import timezone
from pathlib import Path
from loghound.parsers import jsonlog

FIXTURE = Path(__file__).parent / "fixtures" / "sample_json.log"
SYSLOG_FIXTURE = Path(__file__).parent / "fixtures" / "sample_auth.log"


def test_can_parse_positive():
    with open(FIXTURE) as f:
        sample = [line.strip() for line in f.readlines()[:20]]
    assert jsonlog.can_parse(sample)


def test_can_parse_negative_syslog():
    with open(SYSLOG_FIXTURE) as f:
        sample = [line.strip() for line in f.readlines()[:20]]
    assert not jsonlog.can_parse(sample)


def test_parses_valid_lines():
    events = list(jsonlog.parse_file(FIXTURE))
    assert len(events) == 5


def test_first_event_fields():
    events = list(jsonlog.parse_file(FIXTURE))
    e = events[0]
    assert e.username == "jdoe"
    assert e.source_ip == "192.168.1.100"
    assert e.event_type == "INFO"
    assert "User login successful" in e.raw


def test_extra_fields_preserved():
    events = list(jsonlog.parse_file(FIXTURE))
    e = events[2]
    assert e.fields.get("service") == "sshd"


def test_alternative_field_names():
    events = list(jsonlog.parse_file(FIXTURE))
    e = events[3]
    assert e.username == "jdoe"
    assert e.source_ip == "192.168.1.100"
    assert e.event_type == "INFO"


def test_utc_normalization():
    events = list(jsonlog.parse_file(FIXTURE))
    for e in events:
        assert e.timestamp.tzinfo is not None
        assert e.timestamp.tzinfo == timezone.utc


def test_timezone_converted_to_utc():
    events = list(jsonlog.parse_file(FIXTURE))
    e = events[3]
    assert e.timestamp.hour == 4
    assert e.timestamp.minute == 48


def test_epoch_timestamp():
    events = list(jsonlog.parse_file(FIXTURE))
    e = events[4]
    assert e.source_ip == "192.168.1.100"
    assert e.timestamp.tzinfo == timezone.utc
    assert e.timestamp.year == 2026
