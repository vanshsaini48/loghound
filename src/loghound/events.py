from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source: str
    event_type: str
    source_ip: Optional[str]
    username: Optional[str]
    raw: str
    fields: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """A security finding detected by a detection rule."""
    detection_name: str
    severity: str
    timestamp: datetime
    entities: dict[str, str]
    evidence: list[str]
    attack_id: Optional[str]
    description: str
    false_positive_notes: str