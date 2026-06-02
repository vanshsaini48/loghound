from pathlib import Path
from loghound.parsers import nginx

FIXTURE = Path(__file__).parent / "fixtures" / "sample_nginx_access.log"
SYSLOG_FIXTURE = Path(__file__).parent / "fixtures" / "sample_auth.log"


def test_can_parse_positive():
    with open(FIXTURE) as f:
        sample = [line.strip() for line in f.readlines()[:20]]
    assert nginx.can_parse(sample)


def test_can_parse_negative_syslog():
    with open(SYSLOG_FIXTURE) as f:
        sample = [line.strip() for line in f.readlines()[:20]]
    assert not nginx.can_parse(sample)


def test_parses_all_lines():
    events = list(nginx.parse_file(FIXTURE))
    assert len(events) == 3


def test_event_fields():
    events = list(nginx.parse_file(FIXTURE))
    e = events[0]
    assert e.source_ip == "192.168.1.50"
    assert e.event_type == "HTTP_REQUEST"
    assert e.fields["http_method"] == "GET"
    assert e.fields["http_path"] == "/api/health"
    assert e.fields["http_status"] == "200"
    assert e.fields["user_agent"] == "python-requests/2.28.0"
