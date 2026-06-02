"""Streaming detection contract (v2.0).

Every detection implements:
  __init__(config: dict)   — store thresholds and config
  process(event: Event)    — handle one event, yield findings
  finalize()               — yield end-of-stream findings
"""

from __future__ import annotations

from typing import Iterable, Optional, Protocol, runtime_checkable

from ..events import Event, Finding


@runtime_checkable
class StreamingDetection(Protocol):
    """Protocol for v2.0 streaming detections."""

    name: str
    severity: str
    attack_id: Optional[str]

    def process(self, event: Event) -> Iterable[Finding]: ...
    def finalize(self) -> Iterable[Finding]: ...
