"""Tests for FR-3.7 — Password Spraying detection (streaming contract)."""

from datetime import datetime, timedelta

from loghound.events import Event
from loghound.detections.password_spraying import PasswordSpraying


def _run_streaming(det, events):
    findings = []
    for event in events:
        findings.extend(det.process(event))
    findings.extend(det.finalize())
    return findings


def _make_ssh_fail(ip, username, ts):
    return Event(
        timestamp=ts,
        source="syslog",
        event_type="auth",
        source_ip=ip,
        username=username,
        raw=f"Mar 15 14:31:02 server sshd[1000]: Failed password for {username} from {ip} port 44521 ssh2",
        fields={
            "process": "sshd",
            "message": f"Failed password for {username} from {ip} port 44521 ssh2",
        },
    )


def test_detects_password_spraying(test_config):
    """Positive: one IP fails against 10+ distinct usernames in 15 min."""
    base = datetime(2026, 3, 15, 14, 0, 0)
    users = [f"user{i}" for i in range(12)]
    events = [
        _make_ssh_fail("10.0.0.99", u, base + timedelta(seconds=i * 30))
        for i, u in enumerate(users)
    ]
    config = test_config["detections"]["password_spraying"]
    det = PasswordSpraying(config)
    findings = _run_streaming(det, events)

    assert len(findings) == 1
    assert findings[0].detection_name == "password_spraying"
    assert findings[0].entities["source_ip"] == "10.0.0.99"
    assert findings[0].severity == "high"
    assert findings[0].attack_id == "T1110.003"
    assert "10" in findings[0].description  # mentions distinct user count


def test_does_not_flag_below_threshold(test_config):
    """Negative: fewer than 10 distinct usernames — not spraying."""
    base = datetime(2026, 3, 15, 14, 0, 0)
    users = [f"user{i}" for i in range(5)]
    events = [
        _make_ssh_fail("10.0.0.99", u, base + timedelta(seconds=i * 30))
        for i, u in enumerate(users)
    ]
    config = test_config["detections"]["password_spraying"]
    det = PasswordSpraying(config)
    findings = _run_streaming(det, events)
    assert len(findings) == 0


def test_does_not_flag_brute_force_pattern(test_config):
    """Negative: many failures but same username — that's brute force, not spraying."""
    base = datetime(2026, 3, 15, 14, 0, 0)
    events = [
        _make_ssh_fail("10.0.0.99", "root", base + timedelta(seconds=i * 10))
        for i in range(15)
    ]
    config = test_config["detections"]["password_spraying"]
    det = PasswordSpraying(config)
    findings = _run_streaming(det, events)
    assert len(findings) == 0


def test_window_eviction(test_config):
    """Entries outside the window are evicted — slow drip across 30 min should not fire."""
    base = datetime(2026, 3, 15, 14, 0, 0)
    # Spread 12 users across 25 minutes — exceeds 15 min window
    events = [
        _make_ssh_fail("10.0.0.99", f"user{i}", base + timedelta(minutes=i * 2))
        for i in range(12)
    ]
    config = test_config["detections"]["password_spraying"]
    det = PasswordSpraying(config)
    findings = _run_streaming(det, events)
    # With 2-min spacing and 15-min window, at most 8 users in any window
    assert len(findings) == 0
