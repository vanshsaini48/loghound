"""Aggregation: dedup repeated findings and count occurrences."""
from collections import defaultdict
from .models import ScoredFinding


def deduplicate(findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """
    Dedup findings by detection type (ignoring specific entities).
    
    Rationale: "SSH brute force happened 10K times" is more actionable
    than "SSH brute force on IP X happened 3 times, on IP Y happened 2 times..."
    
    Groups by: (detection_name, attack_id)
    For each group: keep first finding, merge entity_risk, set count.
    
    Returns deduplicated list, ranked by count (highest first).
    """
    groups = defaultdict(list)
    
    for sf in findings:
        # Group by detection type, ignoring specific entities
        sig = (sf.finding.detection_name, sf.finding.attack_id)
        groups[sig].append(sf)
    
    result = []
    for sig, group in groups.items():
        canonical = group[0]
        
        # Merge entity risk across all findings in group
        merged_risk = {}
        for sf in group:
            for entity_key, risk_val in sf.entity_risk.items():
                merged_risk[entity_key] = merged_risk.get(entity_key, 0) + risk_val
        
        deduplicated = ScoredFinding(
            finding=canonical.finding,
            suppressed=canonical.suppressed,
            suppression_reason=canonical.suppression_reason,
            ioc_hits=canonical.ioc_hits,
            entity_risk=merged_risk,
            count=len(group),
        )
        result.append(deduplicated)
    
    # Sort by count (highest first), then by total risk
    result.sort(
        key=lambda sf: (-sf.count, -sum(sf.entity_risk.values())),
    )
    
    return result
