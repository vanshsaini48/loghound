"""FR-3.9 — CloudTrail Sensitive Actions detection (streaming).

Flags high-risk AWS API calls visible in CloudTrail:
  - IAM policy changes (PutUserPolicy, AttachUserPolicy, AttachRolePolicy, etc.)
  - Access key creation (CreateAccessKey)
  - S3 bucket policy made public (PutBucketPolicy with Principal: "*")
  - ConsoleLogin without MFA

ATT&CK: T1078.004 (Cloud Accounts), T1098 (Account Manipulation).
"""

from __future__ import annotations

import json
from typing import Iterable, Optional

from ..events import Event, Finding

# IAM mutation events that indicate privilege changes
IAM_SENSITIVE_EVENTS = {
    "CreateAccessKey",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "CreateUser",
    "CreateRole",
    "AddUserToGroup",
    "CreateLoginProfile",
    "UpdateLoginProfile",
}


class CloudTrailSensitive:
    name = "cloudtrail_sensitive"
    severity = "high"
    attack_id: Optional[str] = "T1098"

    def __init__(self, config: dict) -> None:
        pass

    def process(self, event: Event) -> Iterable[Finding]:
        if event.source != "cloudtrail":
            return

        event_name = event.fields.get("event_name", "")

        # Check ConsoleLogin without MFA
        if event_name == "ConsoleLogin":
            mfa = event.fields.get("mfa_authenticated", "")
            if mfa == "false":
                yield Finding(
                    detection_name=self.name,
                    severity="high",
                    timestamp=event.timestamp,
                    entities={
                        "username": event.username or "unknown",
                        "source_ip": event.source_ip or "unknown",
                    },
                    evidence=[event.raw[:500]],
                    attack_id="T1078.004",
                    description=(
                        f"AWS ConsoleLogin without MFA by "
                        f"'{event.username}' from {event.source_ip}"
                    ),
                    false_positive_notes=(
                        "Some service accounts or federated logins may not "
                        "use MFA. Verify this is an interactive user account "
                        "and that MFA should be required."
                    ),
                )
            return

        # Check IAM sensitive actions
        if event_name in IAM_SENSITIVE_EVENTS:
            yield Finding(
                detection_name=self.name,
                severity="high",
                timestamp=event.timestamp,
                entities={
                    "username": event.username or "unknown",
                    "source_ip": event.source_ip or "unknown",
                },
                evidence=[event.raw[:500]],
                attack_id="T1098",
                description=(
                    f"Sensitive IAM action '{event_name}' by "
                    f"'{event.username}' from {event.source_ip}"
                ),
                false_positive_notes=(
                    "IAM changes are normal during infrastructure "
                    "provisioning. Suspicious if performed by an unexpected "
                    "user, from an unusual IP, or outside change windows."
                ),
            )
            return

        # Check S3 bucket policy made public
        if event_name == "PutBucketPolicy":
            req_params = event.fields.get("request_parameters", "")
            if '"Principal": "*"' in req_params or '"Principal":"*"' in req_params:
                yield Finding(
                    detection_name=self.name,
                    severity="critical",
                    timestamp=event.timestamp,
                    entities={
                        "username": event.username or "unknown",
                        "source_ip": event.source_ip or "unknown",
                    },
                    evidence=[event.raw[:500]],
                    attack_id="T1098",
                    description=(
                        f"S3 bucket policy set to public access by "
                        f"'{event.username}' from {event.source_ip}"
                    ),
                    false_positive_notes=(
                        "Some buckets (static websites, public datasets) "
                        "are intentionally public. Verify the bucket name "
                        "and whether public access is authorized."
                    ),
                )

    def finalize(self) -> Iterable[Finding]:
        return ()
