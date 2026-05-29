from datetime import datetime
from pathlib import Path
from loghound.events import Event
from loghound.parsers.syslog import parse_file
from loghound.detections.off_hours_login import OffHoursLogin

def test_detects_off_hours_login():
    """Positive test: login at 2 AM should flag."""
    # Synthetic fixture: one off-hours success
    events = [
        Event(
            timestamp=datetime(2024, 3, 15, 2, 30, 0),  # 02:30 (middle of night)
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
    
    config = {
        "business_hours": {
            "start": "08:00",
            "end": "19:00"
        }
    }
    
    detection = OffHoursLogin()
    findings = detection.run(events, config)
    
    assert len(findings) == 1
    assert findings[0].entities["source_ip"] == "203.0.113.99"
    assert findings[0].severity == "medium"
    assert findings[0].attack_id == "T1078"


def test_does_not_flag_business_hours_login():
    """Negative test: login at 2 PM should not flag."""
    # Use real fixture (all successes are within 08:00-19:00)
    events = list(parse_file(Path('tests/fixtures/sample_auth.log')))
    
    config = {
        "business_hours": {
            "start": "08:00",
            "end": "19:00"
        }
    }
    
    detection = OffHoursLogin()
    findings = detection.run(events, config)
    
    assert len(findings) == 0
