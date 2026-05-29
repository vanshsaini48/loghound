from pathlib import Path
from src.loghound.parsers.syslog import parse_file
from src.loghound.detections.successful_after_brute import SuccessfulAfterBrute


def test_detects_successful_after_brute():
    """Positive case: the fixture has a brute-force run followed by a successful login."""
    events = list(parse_file(Path('tests/fixtures/sample_auth.log')))
    detection = SuccessfulAfterBrute()
    findings = detection.run(events, {"threshold": 5, "lookback_minutes": 60})
    assert len(findings) == 1
    assert findings[0].entities["source_ip"] == "203.0.113.42"
    assert findings[0].severity == "critical"
    assert findings[0].attack_id == "T1110"


def test_does_not_flag_success_without_brute():
    """Negative case: a successful login after only a couple of failures is not a compromise."""
    tmp = Path('tests/fixtures/success_without_brute.log')
    tmp.write_text(
        "Mar 15 14:31:02 ubuntu-server sshd[19102]: Failed password for root from 192.168.1.100 port 44521 ssh2\n"
        "Mar 15 14:31:05 ubuntu-server sshd[19103]: Failed password for root from 192.168.1.100 port 44528 ssh2\n"
        "Mar 15 14:31:10 ubuntu-server sshd[19104]: Accepted password for root from 192.168.1.100 port 44530 ssh2\n"
    )
    events = list(parse_file(tmp))
    detection = SuccessfulAfterBrute()
    findings = detection.run(events, {"threshold": 5, "lookback_minutes": 60})
    assert len(findings) == 0  # Only 2 failures before the success — below threshold
    tmp.unlink()