"""Detection engine — streaming with legacy fallback.

Migrated detections use process(event) / finalize().
Legacy detections still use run(events_list, config).
Once all six detections are migrated, the legacy path is removed.
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
    """Run all enabled detections. Streaming where migrated, legacy fallback."""
    streaming = []
    legacy = []

    for det_cls in REGISTRY:
        rule_config = config.get("detections", {}).get(det_cls.name, {})
        if not rule_config.get("enabled", True):
            continue

        # New-style: __init__(config) with process/finalize
        # Old-style: __init__() with run(events, config)
        try:
            det = det_cls(rule_config)
        except TypeError:
            det = det_cls()

        if hasattr(det, "process") and hasattr(det, "finalize"):
            streaming.append(det)
        else:
            legacy.append((det, rule_config))

    # Legacy detections need the full list — materialize only if needed
    if legacy:
        events_list = list(events) if not isinstance(events, list) else events
        events_to_stream = iter(events_list)
    else:
        events_list = None
        events_to_stream = events

    findings: list[Finding] = []

    # Stream events through migrated detections
    for event in events_to_stream:
        for det in streaming:
            findings.extend(det.process(event))

    for det in streaming:
        findings.extend(det.finalize())

    # Run legacy detections on materialized list
    for det, rule_config in legacy:
        findings.extend(det.run(events_list, rule_config))

    # Sort: critical first, then by timestamp
    findings.sort(
        key=lambda f: (SEVERITY_RANK.get(f.severity, 999), f.timestamp)
    )
    return findings
