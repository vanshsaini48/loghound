"""Triage pipeline: orchestrates allowlist → scoring → IOC → aggregation."""
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
      1. Allowlist suppression
      2. Risk scoring
      3. IOC enrichment + bonus risk
      4. Aggregation
    """
    findings_list = list(findings)

    # Stage 1: Allowlist
    findings_list = allowlist.suppress(
        findings_list,
        config.get("allowlist", {})
    )

    # Stage 2: Scoring
    findings_list = scoring.score(
        findings_list,
        config.get("scoring", {})
    )

    # Stage 3: IOC matching
    findings_list = ioc.match(
        findings_list,
        config.get("ioc", {})
    )

    # Stage 4: Aggregation
    findings_list = aggregate.deduplicate(findings_list)

    findings_list.sort(
        key=lambda f: (
            -sum(f.entity_risk.values()),
            SEVERITY_RANK.get(f.finding.severity, 999),
        ),
        reverse=False,
    )

    return findings_list
