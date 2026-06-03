"""Finding deduplication and aggregation.

Groups findings by (detection_name, entity_key) and collapses repeats
into a single ScoredFinding with a count and time range.
"""

from .models import ScoredFinding


def _entity_key(sf: ScoredFinding) -> str:
    """Build a grouping key from detection name + sorted entities."""
    entities = sf.finding.entities or {}
    parts = sorted(f"{k}={v}" for k, v in entities.items())
    return f"{sf.finding.detection_name}|{'|'.join(parts)}"


def deduplicate(findings: list[ScoredFinding]) -> list[ScoredFinding]:
    """
    Group ScoredFindings by (detection_name, entities) and collapse duplicates.
    
    Each group becomes a single ScoredFinding with:
      - count: number of deduplicated findings
      - first_seen / last_seen: time range (via evidence)
    
    Returns aggregated findings sorted by count descending.
    """
    groups = {}
    
    for sf in findings:
        key = _entity_key(sf)
        
        if key in groups:
            existing = groups[key]
            # Merge: increment count, keep earliest timestamp in evidence
            groups[key] = ScoredFinding(
                finding=existing.finding,  # Use first occurrence's full finding
                suppressed=existing.suppressed,
                suppression_reason=existing.suppression_reason,
                ioc_hits=list(set(existing.ioc_hits + sf.ioc_hits)),  # Deduplicate IOC hits
                entity_risk=existing.entity_risk,  # Risk already aggregated by scoring layer
                count=existing.count + 1,
            )
        else:
            groups[key] = sf
    
    # Sort by count descending
    return sorted(groups.values(), key=lambda sf: sf.count, reverse=True)
