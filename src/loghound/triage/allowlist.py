"""Allowlist suppression for findings.

Suppresses findings whose entities match config-driven IPs or usernames.
"""

from .models import ScoredFinding


def suppress(findings: list, config: dict) -> list[ScoredFinding]:
    """
    Suppress findings based on allowlisted IPs and usernames.
    
    Returns a list of ScoredFinding objects with suppressed flag set.
    """
    ips = set(config.get("ips", []))
    users = set(config.get("users", []))
    
    scored = []
    for f in findings:
        entities = getattr(f, "entities", {})
        source_ip = entities.get("source_ip", "")
        username = entities.get("username", "")
        
        suppressed = False
        reason = None
        
        if source_ip and source_ip in ips:
            suppressed = True
            reason = f"IP {source_ip} is allowlisted"
        elif username and username in users:
            suppressed = True
            reason = f"User {username} is allowlisted"
        
        scored.append(ScoredFinding(
            finding=f,
            suppressed=suppressed,
            suppression_reason=reason,
        ))
    
    return scored
