from datetime import datetime
from pathlib import Path
from loghound.events import Event
from loghound.parsers.syslog import parse_file
from loghound.detections.off_hours_login import OffHoursLogin


def _run_streaming(det, events):
    """Helper: drive a streaming detection over a list of events."""
    findings = []
    for event in events:
        findings.extend(det.process(event))
    findings.extend(det.finalize())
    return findings


def test_detects_off_hours_login(test_config):
    """Positive test: login at 2 AM should flag."""
    events = [
        Event(
            timestamp=datetime(2024, 3, 15, 2, 30, 0),
            source="syslog",
            event_type="auth",
            source_ip="203.0.113.99",
            username="attacker",
            raw="Mar 15 02:30:00 ubuntu-server sshd[12345]: Accepted password for attacker from 203.0.113.99 port 12345 ssh2",
            fields={
                "process": "sshd",
                "message": "Accepted password for attacker from 203.0.113.99 port 12345 ssh2"
            }
        )
    ]

    bh = test_config.get("business_hours", {})
    det = OffHoursLogin({"business_hours": bh})
    findings = _run_streaming(det, events)

    assert len(findings) == 1
    assert findings[0].entities["source_ip"] == "203.0.113.99"
    assert findings[0].severity == "medium"
    assert findings[0].attack_id == "T1078"


def test_does_not_flag_business_hours_login(test_config):
    """Negative test: login at 2 PM should not flag."""
    events = list(parse_file(Path('tests/fixtures/sample_auth.log')))

    bh = test_config.get("business_hours", {})
    det = OffHoursLogin({"business_hours": bh})
    findings = _run_streaming(det, events)

    assert len(findings) == 0
