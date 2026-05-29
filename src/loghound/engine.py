from src.loghound.detections import REGISTRY
from src.loghound.findings import Finding

# Severity ranking (lower rank = higher priority)
SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

def run_engine(events: list, config: dict) -> list[Finding]:
    """
    Run all detections against the event stream.
    Returns sorted findings: critical first, then by timestamp.
    """
    findings = []
    
    for detection in REGISTRY:
        rule_config = config.get("detections", {}).get(detection.name, {})
        
        # Skip if explicitly disabled
        if not rule_config.get("enabled", True):
            continue
        
        # Run the detection
        findings.extend(detection.run(events, rule_config))
    
    # Sort by severity rank (critical first), then by timestamp
    findings.sort(
        key=lambda f: (
            SEVERITY_RANK.get(f.severity, 999),
            f.timestamp
        )
    )
    
    return findings
