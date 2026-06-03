"""Detection for sensitive CloudTrail actions (IAM, S3, console login).

ATT&CK: T1078.004 (Cloud Account), T1098 (Account Manipulation)
"""

from typing import Iterable, Optional
from ..events import Event, Finding


class CloudTrailSensitive:
    """Detect sensitive CloudTrail actions."""
    
    name = "cloudtrail_sensitive_actions"
    severity = "high"
    attack_id: Optional[str] = "T1078.004"
    
    DEFAULT_ACTIONS = {
        "CreateAccessKey",
        "CreatePolicy",
        "PutUserPolicy",
        "AttachUserPolicy",
        "PutBucketPolicy",
        "ConsoleLogin",
    }
    
    def __init__(self, config: dict):
        self.config = config
        self.enabled_actions = set(config.get("enabled_actions", self.DEFAULT_ACTIONS))
    
    def process(self, event: Event) -> Iterable[Finding]:
        """Check if this event is a sensitive CloudTrail action."""
        if event.source != "cloudtrail":
            return
        
        event_name = event.fields.get("event_name", "")
        if not event_name:
            return
        
        if event_name not in self.enabled_actions:
            return
        
        description = f"Sensitive CloudTrail action: {event_name}"
        severity = self.severity
        attack_id = self.attack_id
        username = event.username or "unknown"
        
        if event_name == "CreateAccessKey":
            description = f"CreateAccessKey created for user {username}"
            attack_id = "T1098"
        elif event_name == "PutBucketPolicy":
            description = "S3 bucket policy changed (potential public access)"
            severity = "critical"
        elif event_name == "ConsoleLogin":
            mfa_auth = event.fields.get("mfa_authenticated", "")
            has_mfa = mfa_auth in (True, "true", "True")
            
            if not has_mfa:
                description = f"ConsoleLogin without MFA by {username}"
                severity = "critical"
            else:
                return
        elif event_name in ("CreatePolicy", "PutUserPolicy", "AttachUserPolicy"):
            description = f"IAM policy change: {event_name} by {username}"
            attack_id = "T1098"
        
        yield Finding(
            detection_name=self.name,
            severity=severity,
            timestamp=event.timestamp,
            entities={
                "username": event.username or "unknown",
                "source_ip": event.source_ip or "unknown",
            },
            evidence=[event.raw[:200]],
            attack_id=attack_id,
            description=description,
            false_positive_notes="Verify the user and action are authorized for this account.",
        )
    
    def finalize(self) -> Iterable[Finding]:
        """No end-of-stream findings for this detection."""
        return []
