"""Aggregation: dedup repeated findings and count occurrences."""
from collections import defaultdict
from .models import ScoredFinding


def deduplicate(findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """
    Deduplicate repeated findings for the SAME entity.

    Example:

        ssh_brute_force + source_ip=1.1.1.1
        ssh_brute_force + source_ip=1.1.1.1

    becomes:

        ssh_brute_force + source_ip=1.1.1.1 (count=2)

    But:

        ssh_brute_force + source_ip=1.1.1.1
        ssh_brute_force + source_ip=2.2.2.2

    remain separate findings.

    Returns findings sorted by count then risk.
    """
    groups = defaultdict(list)

    for sf in findings:
        sig = (
            sf.finding.detection_name,
            tuple(sorted(sf.finding.entities.items())),
        )
        groups[sig].append(sf)

    result = []

    for group in groups.values():
        canonical = group[0]

        merged_risk = {}
        merged_iocs = set()

        for sf in group:
            for entity_key, risk_val in sf.entity_risk.items():
                merged_risk[entity_key] = (
                    merged_risk.get(entity_key, 0) + risk_val
                )

            for hit in sf.ioc_hits:
                merged_iocs.add(hit)

        result.append(
            ScoredFinding(
                finding=canonical.finding,
                suppressed=canonical.suppressed,
                suppression_reason=canonical.suppression_reason,
                ioc_hits=sorted(merged_iocs),
                entity_risk=merged_risk,
                count=len(group),
            )
        )

    result.sort(
        key=lambda sf: (
            -sf.count,
            -sum(sf.entity_risk.values()),
        )
    )

    return result
