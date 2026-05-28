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

