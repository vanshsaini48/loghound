"""Detection engine — pure streaming (v2.0).

All detections implement process(event) / finalize().
Events are iterated exactly once; nothing is materialized.
"""

from __future__ import annotations

from .detections import REGISTRY
from .events import Finding

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def run_engine(events, config: dict) -> list[Finding]:
    """Stream events through all enabled detections in a single pass."""
    detections = []
    for det_cls in REGISTRY:
        rule_config = config.get("detections", {}).get(det_cls.name, {})
        if not rule_config.get("enabled", True):
            continue
        detections.append(det_cls(rule_config))

    findings: list[Finding] = []

    for event in events:
        for det in detections:
            findings.extend(det.process(event))

    for det in detections:
        findings.extend(det.finalize())

    findings.sort(
        key=lambda f: (SEVERITY_RANK.get(f.severity, 999), f.timestamp)
    )
    return findings
