"""Tests for CloudTrail JSON parser."""

from datetime import timezone
from pathlib import Path

from loghound.parsers import cloudtrail
from loghound.parsers.detector import detect_and_parse

FIXTURE = Path(__file__).parent / "fixtures" / "sample_cloudtrail.json"


def test_can_parse_positive():
    with open(FIXTURE) as f:
        sample = [line.strip() for line in f.readlines()[:50]]
    assert cloudtrail.can_parse(sample)


def test_can_parse_negative_syslog():
    lines = ["Mar 15 14:31:02 ubuntu-server sshd[1000]: Failed password for root"]
    assert not cloudtrail.can_parse(lines)


def test_parses_all_records():
    events = list(cloudtrail.parse_file(FIXTURE))
    assert len(events) == 7


def test_event_source_is_cloudtrail():
    events = list(cloudtrail.parse_file(FIXTURE))
    for e in events:
        assert e.source == "cloudtrail"


def test_maps_source_ip():
    events = list(cloudtrail.parse_file(FIXTURE))
    assert events[0].source_ip == "203.0.113.50"
    assert events[1].source_ip == "198.51.100.77"


def test_maps_username_from_arn():
    events = list(cloudtrail.parse_file(FIXTURE))
    assert events[0].username == "user/alice"


def test_maps_event_type_to_event_name():
    events = list(cloudtrail.parse_file(FIXTURE))
    assert events[0].event_type == "ConsoleLogin"
    assert events[2].event_type == "CreateAccessKey"


def test_utc_timestamps():
    events = list(cloudtrail.parse_file(FIXTURE))
    for e in events:
        assert e.timestamp.tzinfo is not None
        assert e.timestamp.tzinfo == timezone.utc


def test_mfa_in_fields():
    events = list(cloudtrail.parse_file(FIXTURE))
    # First record: MFA true
    assert events[0].fields.get("mfa_authenticated") == "true"
    # Second record: MFA false
    assert events[1].fields.get("mfa_authenticated") == "false"


def test_event_name_in_fields():
    events = list(cloudtrail.parse_file(FIXTURE))
    assert events[2].fields["event_name"] == "CreateAccessKey"


def test_auto_detect_cloudtrail():
    name, events = detect_and_parse(FIXTURE)
    events_list = list(events)
    assert "cloudtrail" in name
    assert len(events_list) == 7


def test_format_override_cloudtrail():
    name, events = detect_and_parse(FIXTURE, format_override="cloudtrail")
    assert name == "cloudtrail"
    assert len(list(events)) == 7
