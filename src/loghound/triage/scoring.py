"""Entity risk scoring: calculate per-entity risk based on finding severity."""
from typing import Iterable
from .models import ScoredFinding

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 4,
    "medium": 2,
    "low": 1,
}


def score(findings: Iterable[Finding], config: dict) -> list[ScoredFinding]:
    """
    Calculate per-entity risk score.
    
    Each entity (IP, user) accumulates risk based on finding severity.
    
    Config:
      scoring:
        severity_weights: { critical: 10, high: 4, medium: 2, low: 1 }
    """
    weights = config.get("severity_weights", SEVERITY_WEIGHTS)
    
    result = []
    for sf in findings:
        # If not already a ScoredFinding, wrap it
        if not isinstance(sf, ScoredFinding):
            sf = ScoredFinding(finding=sf)
        
        # Calculate risk for each entity
        entity_risk = {}
        severity_weight = weights.get(sf.finding.severity, 0)
        
        for entity_type, entity_value in sf.finding.entities.items():
            key = f"{entity_type}:{entity_value}"
            entity_risk[key] = severity_weight
        
        # Update the ScoredFinding (create a new one since frozen)
        result.append(ScoredFinding(
            finding=sf.finding,
            suppressed=sf.suppressed,
            suppression_reason=sf.suppression_reason,
            ioc_hits=sf.ioc_hits,
            entity_risk=entity_risk,
        ))
    
    return result
