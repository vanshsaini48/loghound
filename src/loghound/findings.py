from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class Finding:
    detection_name: str
    severity: str
    timestamp: datetime
    entities: dict[str, str]
    evidence: list[str]
    attack_id: Optional[str]
    description: str
    false_positive_notes: str
