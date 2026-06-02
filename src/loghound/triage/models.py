"""Data models for the triage layer."""
from dataclasses import dataclass, field
from ..events import Finding


@dataclass(frozen=True)
class ScoredFinding:
    """A Finding with triage metadata: suppression, IOC hits, and entity risk scores."""
    finding: Finding
    suppressed: bool = False
    suppression_reason: str | None = None
    ioc_hits: list[str] = field(default_factory=list)
    entity_risk: dict[str, int] = field(default_factory=dict)
    # entity_risk maps "ip:10.0.1.1" or "user:alice" → risk score
