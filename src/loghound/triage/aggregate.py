"""Aggregation: dedup repeated findings and count occurrences."""
from typing import Iterable
from collections import defaultdict
from .models import ScoredFinding


def deduplicate(findings: Iterable[Iterable[ScoredFinding]]) -> list[ScoredFinding]:
    """
    Dedup findings by (detection_name, entities, attack_id).
    Count occurrences and merge entity risks.
    
    For now, returns findings as-is (stub).
    TODO: Group by signature, aggregate counts, merge entity risk.
    """
    return list(findings)
