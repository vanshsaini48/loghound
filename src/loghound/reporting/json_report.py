"""JSON reporter: export findings as JSON-lines with stable schema."""
import json
from datetime import datetime
from typing import Iterable
from ..triage.models import ScoredFinding


def generate_json_report(
    scored_findings: Iterable[ScoredFinding],
    log_file: str,
    event_count: int,
) -> str:
    """
    Generate JSON-lines report from scored findings.
    
    Schema (one object per line):
    {
      "detection_name": "ssh_brute_force",
      "severity": "high",
      "attack_id": "T1110",
      "timestamp": "2026-06-02T14:30:45+00:00",
      "entities": {"source_ip": "10.0.1.5", "username": "admin"},
      "description": "...",
      "evidence": [...],
      "false_positive_notes": "...",
      "count": 42,
      "suppressed": false,
      "suppression_reason": null,
      "ioc_hits": ["10.0.1.5"],
      "entity_risk": {"source_ip:10.0.1.5": 12}
    }
    
    Returned as JSON-lines (one object per line) for streaming consumption.
    """
    lines = []
    
    # Header comment (not valid JSON, for reference)
    lines.append(f'# loghound JSON report — {log_file} ({event_count} events processed)')
    lines.append(f'# Generated: {datetime.now().isoformat()}')
    
    for sf in scored_findings:
        obj = {
            "detection_name": sf.finding.detection_name,
            "severity": sf.finding.severity,
            "attack_id": sf.finding.attack_id,
            "timestamp": sf.finding.timestamp.isoformat(),
            "entities": sf.finding.entities,
            "description": sf.finding.description,
            "evidence": sf.finding.evidence,
            "false_positive_notes": sf.finding.false_positive_notes,
            "count": sf.count,
            "suppressed": sf.suppressed,
            "suppression_reason": sf.suppression_reason,
            "ioc_hits": sf.ioc_hits,
            "entity_risk": sf.entity_risk,
        }
        lines.append(json.dumps(obj))
    
    return "\n".join(lines) + "\n"
