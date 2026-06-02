"""Data models for the triage layer."""
from dataclasses import dataclass, field
from ..events import Finding


@dataclass(frozen=True)
class ScoredFinding:
    """A Finding with triage metadata: suppression, IOC hits, entity risk scores, and dedup count."""
    finding: Finding
    suppressed: bool = False
    suppression_reason: str | None = None
    ioc_hits: list[str] = field(default_factory=list)
    entity_risk: dict[str, int] = field(default_factory=dict)
    count: int = 1  # How many times this finding was deduplicated
