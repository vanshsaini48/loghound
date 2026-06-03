"""Detection for sensitive CloudTrail actions (IAM, S3, console login).

Flags:
- IAM policy changes (CreatePolicy, AttachUserPolicy, etc.)
- Access key creation (CreateAccessKey)
- S3 bucket policy made public (PutBucketPolicy)
- Console login without MFA (ConsoleLogin with MFARequired error)

ATT&CK: T1078.004 (Cloud Account), T1098 (Account Manipulation)
"""

from typing import Iterable, Optional
from ..events import Event, Finding


class CloudTrailSensitive:
    """Detect sensitive CloudTrail actions."""
    
    name = "cloudtrail_sensitive_actions"
    severity = "high"
    attack_id: Optional[str] = "T1078.004"
    
    def __init__(self, config: dict):
        self.config = config
        self.enabled_actions = config.get("enabled_actions", [
            "CreateAccessKey",
            "CreatePolicy",
            "AttachUserPolicy",
            "PutBucketPolicy",
            "ConsoleLogin",
        ])
    
    def process(self, event: Event) -> Iterable[Finding]:
        """Check if this event is a sensitive CloudTrail action."""
        if event.source != "cloudtrail":
            return
        
        event_name = event.fields.get("eventName", "")
        
        # Check for sensitive actions
        if event_name not in self.enabled_actions:
            return
        
        description = ""
        if event_name == "CreateAccessKey":
            description = f"New access key created in CloudTrail"
        elif event_name == "PutBucketPolicy":
            description = "S3 bucket policy changed"
        elif event_name == "ConsoleLogin":
            error_code = event.fields.get("errorCode", "")
            if error_code == "MFARequired":
                description = "Console login attempted without MFA"
            else:
                description = "Console login detected"
        else:
            description = f"Sensitive CloudTrail action: {event_name}"
        
        yield Finding(
            detection_name=self.name,
            severity=self.severity,
            timestamp=event.timestamp,
            entities={
                "username": event.username or "unknown",
                "source_ip": event.source_ip or "unknown",
            },
            evidence=[event.raw[:200]],
            attack_id=self.attack_id,
            description=description,
            false_positive_notes="Verify the user and action are authorized for this account.",
        )
    
    def finalize(self) -> Iterable[Finding]:
        """No end-of-stream findings for this detection."""
        return []
