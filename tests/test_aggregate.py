"""Tests for finding deduplication and aggregation."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from loghound.triage.aggregate import deduplicate
from loghound.triage.models import ScoredFinding


@dataclass(frozen=True)
class FakeFinding:
    detection_name: str = "ssh_brute_force"
    severity: str = "high"
    timestamp: datetime = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    entities: dict = field(default_factory=lambda: {"source_ip": "192.168.1.100"})
    evidence: list = field(default_factory=lambda: ["Failed password for root"])
    attack_id: Optional[str] = "T1110"
    description: str = "Brute force detected"
    false_positive_notes: str = ""


def fake_scored_finding(finding=None, **kwargs) -> ScoredFinding:
    """Helper to create a ScoredFinding."""
    if finding is None:
        finding = FakeFinding()
    defaults = {
        "finding": finding,
        "suppressed": False,
        "suppression_reason": None,
        "ioc_hits": [],
        "entity_risk": {},
        "count": 1,
    }
    defaults.update(kwargs)
    return ScoredFinding(**defaults)


def test_identical_findings_collapse():
    """Three identical findings should collapse into one with count=3."""
    sf1 = fake_scored_finding()
    sf2 = fake_scored_finding()
    sf3 = fake_scored_finding()
    result = deduplicate([sf1, sf2, sf3])
    assert len(result) == 1
    assert result[0].count == 3


def test_different_detections_stay_separate():
    """Findings from different detections should not merge."""
    f1 = FakeFinding(detection_name="ssh_brute_force")
    f2 = FakeFinding(detection_name="off_hours_login")
    sf1 = fake_scored_finding(f1)
    sf2 = fake_scored_finding(f2)
    result = deduplicate([sf1, sf2])
    assert len(result) == 2


def test_different_entities_stay_separate():
    """Same detection but different entities should not merge."""
    f1 = FakeFinding(entities={"source_ip": "10.0.0.1"})
    f2 = FakeFinding(entities={"source_ip": "10.0.0.2"})
    sf1 = fake_scored_finding(f1)
    sf2 = fake_scored_finding(f2)
    result = deduplicate([sf1, sf2])
    assert len(result) == 2


def test_sorted_by_count_descending():
    """Results should be sorted by count, highest first."""
    f1 = FakeFinding(entities={"source_ip": "10.0.0.1"})
    f2 = FakeFinding(entities={"source_ip": "10.0.0.2"})
    
    sf1 = fake_scored_finding(f1)
    sf2 = fake_scored_finding(f2)
    sf2_dup1 = fake_scored_finding(f2)
    sf2_dup2 = fake_scored_finding(f2)
    
    result = deduplicate([sf1, sf2, sf2_dup1, sf2_dup2])
    assert result[0].count == 3
    assert result[0].finding.entities["source_ip"] == "10.0.0.2"
    assert result[1].count == 1


def test_empty_input():
    """No findings should return empty list."""
    assert deduplicate([]) == []


def test_preserves_suppression_status():
    """deduplicate should preserve suppressed status."""
    f = FakeFinding()
    sf = fake_scored_finding(f, suppressed=True, suppression_reason="Test")
    result = deduplicate([sf])
    assert result[0].suppressed is True
    assert result[0].suppression_reason == "Test"
