"""Tests for allowlist suppression."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from loghound.triage.allowlist import suppress
from loghound.triage.models import ScoredFinding


@dataclass(frozen=True)
class FakeFinding:
    detection_name: str = "ssh_brute_force"
    severity: str = "high"
    timestamp: datetime = datetime(2026, 6, 1, tzinfo=timezone.utc)
    entities: dict = field(default_factory=lambda: {"source_ip": "192.168.1.100", "username": "root"})
    evidence: list = field(default_factory=list)
    attack_id: Optional[str] = "T1110"
    description: str = "Brute force detected"
    false_positive_notes: str = ""


def test_ip_allowlisted():
    """Finding with an allowlisted IP should be suppressed."""
    config = {"ips": ["192.168.1.100"], "users": []}
    result = suppress([FakeFinding()], config)
    assert len(result) == 1
    assert result[0].suppressed is True
    assert "192.168.1.100" in result[0].suppression_reason


def test_user_allowlisted():
    """Finding with an allowlisted username should be suppressed."""
    config = {"ips": [], "users": ["backup-svc"]}
    finding = FakeFinding(entities={"source_ip": "10.0.0.1", "username": "backup-svc"})
    result = suppress([finding], config)
    assert result[0].suppressed is True
    assert "backup-svc" in result[0].suppression_reason


def test_not_allowlisted():
    """Finding with no allowlisted entities should not be suppressed."""
    config = {"ips": ["10.0.0.5"], "users": ["svc-account"]}
    result = suppress([FakeFinding()], config)
    assert result[0].suppressed is False
    assert result[0].suppression_reason is None


def test_empty_allowlist():
    """Empty allowlist suppresses nothing."""
    config = {}
    result = suppress([FakeFinding()], config)
    assert result[0].suppressed is False


def test_suppress_multiple():
    """suppress() handles multiple findings."""
    config = {"ips": ["192.168.1.100"], "users": []}
    findings = [
        FakeFinding(),
        FakeFinding(entities={"source_ip": "10.0.0.1", "username": "admin"})
    ]
    result = suppress(findings, config)
    assert len(result) == 2
    assert result[0].suppressed is True
    assert result[1].suppressed is False
