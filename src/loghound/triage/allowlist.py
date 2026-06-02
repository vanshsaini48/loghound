"""Allowlist suppression: filter or downgrade findings by IP/user."""
from typing import Iterable
from ..events import Finding
from .models import ScoredFinding


def suppress(findings: Iterable[Finding], config: dict) -> list[ScoredFinding]:
    """
    Suppress or downgrade findings for allowlisted IPs and users.
    
    Config:
      allowlist:
        ips: ["10.0.0.5", "192.168.1.1"]
        users: ["backup-svc", "monitoring"]
    """
    allowlisted_ips = set(config.get("ips", []))
    allowlisted_users = set(config.get("users", []))
    
    result = []
    for finding in findings:
        suppressed = False
        reason = None
        
        source_ip = finding.entities.get("source_ip")
        username = finding.entities.get("username")
        
        if source_ip in allowlisted_ips:
            suppressed = True
            reason = f"IP {source_ip} is allowlisted"
        elif username in allowlisted_users:
            suppressed = True
            reason = f"User {username} is allowlisted"
        
        result.append(ScoredFinding(
            finding=finding,
            suppressed=suppressed,
            suppression_reason=reason,
        ))
    
    return result
