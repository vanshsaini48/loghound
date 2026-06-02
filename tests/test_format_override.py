import pytest
from pathlib import Path
from loghound.parsers.detector import detect_and_parse

SYSLOG_FIXTURE = Path(__file__).parent / "fixtures" / "sample_auth.log"
JSON_FIXTURE = Path(__file__).parent / "fixtures" / "sample_json.log"


def test_override_forces_parser():
    name, events = detect_and_parse(SYSLOG_FIXTURE, format_override='syslog')
    assert name == 'syslog'
    assert len(list(events)) > 0


def test_override_invalid_format():
    with pytest.raises(ValueError, match="Unknown format"):
        detect_and_parse(SYSLOG_FIXTURE, format_override='nonexistent')


def test_auto_detect_still_works():
    name, events = detect_and_parse(JSON_FIXTURE)
    assert 'jsonlog' in name
    assert len(list(events)) > 0
