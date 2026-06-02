"""Entity risk scoring: calculate per-entity risk based on finding severity."""
from typing import Iterable
from .models import ScoredFinding


SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 4,
    "medium": 2,
    "low": 1,
}


def score(findings: Iterable[ScoredFinding], config: dict) -> list[ScoredFinding]:
    """
    Calculate per-entity risk score, aggregated across all findings.
    
    Two-pass approach:
      1. Accumulate risk per entity across all findings
      2. Apply aggregated totals to each finding
    
    Config:
      scoring:
        severity_weights: { critical: 10, high: 4, medium: 2, low: 1 }
    
    If an entity (IP, user) appears in multiple findings, its total risk
    is shown on each. Example: IP 10.0.1.5 in brute_force (high=4) + 
    off_hours (medium=2) = total risk 6 on both findings.
    """
    weights = config.get("severity_weights", SEVERITY_WEIGHTS)
    
    # Convert to list for multiple passes
    findings_list = list(findings)
    
    # Pass 1: accumulate risk per entity
    entity_totals = {}  # entity_key → total risk
    for sf in findings_list:
        severity_weight = weights.get(sf.finding.severity, 0)
        
        for entity_type, entity_value in sf.finding.entities.items():
            key = f"{entity_type}:{entity_value}"
            entity_totals[key] = entity_totals.get(key, 0) + severity_weight
    
    # Pass 2: apply aggregated risk to each finding
    result = []
    for sf in findings_list:
        # Build entity_risk dict with aggregated totals
        entity_risk = {}
        for entity_type, entity_value in sf.finding.entities.items():
            key = f"{entity_type}:{entity_value}"
            entity_risk[key] = entity_totals[key]
        
        # Update the ScoredFinding (create a new one since frozen)
        result.append(ScoredFinding(
            finding=sf.finding,
            suppressed=sf.suppressed,
            suppression_reason=sf.suppression_reason,
            ioc_hits=sf.ioc_hits,
            entity_risk=entity_risk,
        ))
    
    return result
