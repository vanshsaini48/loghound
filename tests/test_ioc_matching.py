from pathlib import Path

from loghound.events import Finding
from loghound.triage.models import ScoredFinding
from loghound.triage.ioc import match


def test_ioc_match_adds_hit_and_risk_bonus(tmp_path):
    ioc_file = tmp_path / "iocs.txt"
    ioc_file.write_text("203.0.113.42\n")

    finding = Finding(
        detection_name="ssh_brute_force",
        severity="high",
        timestamp=None,
        entities={"source_ip": "203.0.113.42"},
        evidence=[],
        attack_id="T1110",
        description="test",
        false_positive_notes="",
    )

    scored = ScoredFinding(
        finding=finding,
        entity_risk={"source_ip:203.0.113.42": 15},
    )

    result = match(
        [scored],
        {
            "list_path": str(ioc_file),
            "bonus": 5,
        },
    )

    assert result[0].ioc_hits == ["203.0.113.42"]
    assert result[0].entity_risk["source_ip:203.0.113.42"] == 20


def test_ioc_match_no_hit():
    finding = Finding(
        detection_name="ssh_brute_force",
        severity="high",
        timestamp=None,
        entities={"source_ip": "198.51.100.10"},
        evidence=[],
        attack_id="T1110",
        description="test",
        false_positive_notes="",
    )

    scored = ScoredFinding(
        finding=finding,
        entity_risk={"source_ip:198.51.100.10": 15},
    )

    result = match(
        [scored],
        {
            "list_path": "does-not-exist.txt",
            "bonus": 5,
        },
    )

    assert result[0].ioc_hits == []
    assert result[0].entity_risk["source_ip:198.51.100.10"] == 15
