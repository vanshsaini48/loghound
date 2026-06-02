"""Tests for FR-3.8 — New Source IP for User detection (streaming contract)."""

from datetime import datetime, timedelta

from loghound.events import Event
from loghound.detections.new_ip_for_user import NewIPForUser


def _run_streaming(det, events):
    findings = []
    for event in events:
        findings.extend(det.process(event))
    findings.extend(det.finalize())
    return findings


def _make_ssh_success(user, ip, ts):
    return Event(
        timestamp=ts,
        source="syslog",
        event_type="auth",
        source_ip=ip,
        username=user,
        raw=f"Mar 15 08:00:00 server sshd[1000]: Accepted password for {user} from {ip} port 51234 ssh2",
        fields={
            "process": "sshd",
            "message": f"Accepted password for {user} from {ip} port 51234 ssh2",
        },
    )


def test_flags_second_ip_for_user(test_config):
    """Positive: user logs in from a new IP after a known one."""
    base = datetime(2026, 3, 15, 8, 0, 0)
    events = [
        _make_ssh_success("alice", "192.168.1.50", base),
        _make_ssh_success("alice", "10.0.0.99", base + timedelta(hours=2)),
    ]
    config = test_config["detections"]["new_ip_for_user"]
    det = NewIPForUser(config)
    findings = _run_streaming(det, events)

    assert len(findings) == 1
    assert findings[0].detection_name == "new_ip_for_user"
    assert findings[0].entities["username"] == "alice"
    assert findings[0].entities["source_ip"] == "10.0.0.99"
    assert findings[0].severity == "low"
    assert findings[0].attack_id == "T1078"
    assert "192.168.1.50" in findings[0].description  # mentions known IP


def test_no_finding_for_first_login(test_config):
    """Negative: first login from any IP is not suspicious."""
    events = [
        _make_ssh_success("bob", "192.168.1.50", datetime(2026, 3, 15, 8, 0, 0)),
    ]
    config = test_config["detections"]["new_ip_for_user"]
    det = NewIPForUser(config)
    findings = _run_streaming(det, events)
    assert len(findings) == 0


def test_no_finding_for_repeated_ip(test_config):
    """Negative: same IP used again is not new."""
    base = datetime(2026, 3, 15, 8, 0, 0)
    events = [
        _make_ssh_success("alice", "192.168.1.50", base),
        _make_ssh_success("alice", "192.168.1.50", base + timedelta(hours=1)),
    ]
    config = test_config["detections"]["new_ip_for_user"]
    det = NewIPForUser(config)
    findings = _run_streaming(det, events)
    assert len(findings) == 0


def test_multiple_new_ips_emit_multiple_findings(test_config):
    """Positive: each genuinely new IP produces a finding."""
    base = datetime(2026, 3, 15, 8, 0, 0)
    events = [
        _make_ssh_success("alice", "192.168.1.50", base),
        _make_ssh_success("alice", "10.0.0.1", base + timedelta(hours=1)),
        _make_ssh_success("alice", "10.0.0.2", base + timedelta(hours=2)),
    ]
    config = test_config["detections"]["new_ip_for_user"]
    det = NewIPForUser(config)
    findings = _run_streaming(det, events)
    assert len(findings) == 2


def test_independent_per_user(test_config):
    """Users tracked independently — alice's IPs don't affect bob."""
    base = datetime(2026, 3, 15, 8, 0, 0)
    events = [
        _make_ssh_success("alice", "192.168.1.50", base),
        _make_ssh_success("bob", "192.168.1.50", base + timedelta(minutes=5)),
        # Same IP for bob is his first — no finding
    ]
    config = test_config["detections"]["new_ip_for_user"]
    det = NewIPForUser(config)
    findings = _run_streaming(det, events)
    assert len(findings) == 0
