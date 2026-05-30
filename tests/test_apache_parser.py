import pytest
from pathlib import Path
from loghound.parsers.apache import parse_file, can_parse
from loghound.events import Event

def test_apache_can_parse_clf():
    """Test that can_parse recognizes Common Log Format."""
    sample = ['192.168.1.100 - - [30/May/2026:14:22:15 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "Mozilla/5.0"']
    assert can_parse(sample) == True

def test_apache_cannot_parse_syslog():
    """Test that can_parse rejects syslog format."""
    sample = ['May 30 14:22:15 server sshd[1234]: Failed password for invalid user admin from 203.0.113.42']
    assert can_parse(sample) == False

def test_apache_parse_valid_request():
    """Test parsing a valid Apache log line."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample_access.log"
    events = list(parse_file(fixture_path))
    
    # Should parse at least some events
    assert len(events) > 0
    
    # Check first event structure
    event = events[0]
    assert isinstance(event, Event)
    assert event.source_ip == "192.168.1.100"
    assert event.event_type == "HTTP_REQUEST"
    assert "http_method" in event.fields
    assert event.fields["http_method"] == "GET"
    assert event.fields["http_status"] == "200"

def test_apache_parse_extracts_user_agent():
    """Test that user_agent is extracted correctly."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample_access.log"
    events = list(parse_file(fixture_path))
    
    # Find event with sqlmap user agent
    sqlmap_event = next((e for e in events if "sqlmap" in e.fields.get("user_agent", "")), None)
    assert sqlmap_event is not None
    assert sqlmap_event.fields["user_agent"] == "sqlmap/1.4"
