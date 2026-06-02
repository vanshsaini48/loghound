"""JSON reporter: export findings as JSON-lines with stable schema."""
import json
from typing import Iterable
from ..triage.models import ScoredFinding


def generate_json_report(
    scored_findings: Iterable[ScoredFinding],
    log_file: str,
    event_count: int,
) -> str:
    """
    Generate JSON-lines report from scored findings.

    One JSON object per line.
    No comments or header lines.
    """

    lines = []

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
