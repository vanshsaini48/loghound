"""Tests for FR-3.6 — Privilege Escalation Indicators (streaming contract)."""

from datetime import datetime, timedelta

from loghound.events import Event
from loghound.detections.privilege_escalation import PrivilegeEscalation


def _run_streaming(det, events):
    findings = []
    for event in events:
        findings.extend(det.process(event))
    findings.extend(det.finalize())
    return findings


def make_event(
    username: str,
    event_type: str,
    timestamp: datetime,
    source: str = "auth.log",
) -> Event:
    return Event(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        source_ip="10.0.0.50",
        username=username,
        raw=f"{username} {event_type} at {timestamp}",
        fields={},
    )


def test_detects_exploit_fail_then_success(test_config):
    """Failures followed by success within 5min = exploit attempt."""
    base_time = datetime(2026, 5, 30, 12, 0, 0)
    events = [
        make_event("alice", "SUDO_FAILURE", base_time),
        make_event("alice", "SUDO_SUCCESS", base_time + timedelta(minutes=2)),
    ]
    config = test_config["detections"]["privilege_escalation"]
    findings = _run_streaming(PrivilegeEscalation(config), events)
    assert len(findings) == 2
    exploit = next(f for f in findings if f.severity == "high")
    assert "escalation" in exploit.description.lower()


def test_detects_first_time_sudo(test_config):
    """Any sudo success is new privilege usage if it's the first."""
    events = [
        make_event("bob", "SUDO_SUCCESS", datetime(2026, 5, 30, 12, 0, 0)),
    ]
    config = test_config["detections"]["privilege_escalation"]
    findings = _run_streaming(PrivilegeEscalation(config), events)
    assert len(findings) == 1
    assert findings[0].severity == "medium"


def test_ignores_fail_without_success(test_config):
    """Failures alone are not a finding (may be typos)."""
    events = [
        make_event("charlie", "SUDO_FAILURE", datetime(2026, 5, 30, 12, 0, 0)),
    ]
    config = test_config["detections"]["privilege_escalation"]
    assert _run_streaming(PrivilegeEscalation(config), events) == []


def test_ignores_fail_success_outside_window(test_config):
    """Success outside 5min window is not an exploit, but still first-time."""
    base_time = datetime(2026, 5, 30, 12, 0, 0)
    events = [
        make_event("dave", "SUDO_FAILURE", base_time),
        make_event("dave", "SUDO_SUCCESS", base_time + timedelta(minutes=10)),
    ]
    config = test_config["detections"]["privilege_escalation"]
    findings = _run_streaming(PrivilegeEscalation(config), events)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
