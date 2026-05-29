from pathlib import Path
from src.loghound.parsers.syslog import parse_file
from src.loghound.detections.ssh_brute_force import SSHBruteForce


def test_detects_brute_force():
    """Positive case: the fixture contains a real brute-force run."""
    events = list(parse_file(Path('tests/fixtures/sample_auth.log')))
    detection = SSHBruteForce()
    findings = detection.run(events, {"threshold": 5, "window_minutes": 10})

    assert len(findings) == 1
    assert findings[0].entities["source_ip"] == "203.0.113.42"
    assert findings[0].severity == "high"
    assert findings[0].attack_id == "T1110"


def test_does_not_flag_below_threshold():
    """Negative case: a few failures from one IP don't cross the threshold."""
    tmp = Path('tests/fixtures/brute_force_below_threshold.log')
    tmp.write_text(
        "Mar 15 14:31:02 ubuntu-server sshd[19102]: Failed password for root from 192.168.1.100 port 44521 ssh2\n"
        "Mar 15 14:31:05 ubuntu-server sshd[19103]: Failed password for root from 192.168.1.100 port 44528 ssh2\n"
    )

    events = list(parse_file(tmp))
    detection = SSHBruteForce()
    findings = detection.run(events, {"threshold": 5, "window_minutes": 10})

    assert len(findings) == 0  # Below threshold, no flag
    tmp.unlink()
