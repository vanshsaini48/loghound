"""Triage pipeline: orchestrates allowlist → IOC → scoring → aggregation."""
from typing import Iterable
from ..events import Finding
from .models import ScoredFinding
from . import allowlist, ioc, scoring, aggregate

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def run_triage(
    findings: Iterable[Finding],
    config: dict,
) -> list[ScoredFinding]:
    """
    Run findings through the triage pipeline.
    
    Stages:
      1. Allowlist suppression (suppress/downgrade by IP/user)
      2. IOC matching (flag IPs in IOC list)
      3. Scoring (calculate per-entity risk)
      4. Aggregation (dedup repeated findings)
    
    Returns ranked list of ScoredFinding.
    """
    # Convert to list for multiple passes
    findings_list = list(findings)
    
    # Stage 1: Allowlist
    findings_list = allowlist.suppress(findings_list, config.get("allowlist", {}))
    
    # Stage 2: IOC matching
    findings_list = ioc.match(findings_list, config.get("ioc", {}))
    
    # Stage 3: Scoring
    findings_list = scoring.score(findings_list, config.get("scoring", {}))
    
    # Stage 4: Aggregation
    findings_list = aggregate.deduplicate(findings_list)
    
    # Rank by total entity risk (descending), then severity
    findings_list.sort(
        key=lambda f: (
            -sum(f.entity_risk.values()),
            SEVERITY_RANK.get(f.finding.severity, 999),
        ),
        reverse=False,
    )
    
    return findings_list
