"""FR-3.6 — Privilege Escalation Indicators.

Detects two patterns in sudo logs:
1. Sudo successes preceded by failures within 5 minutes (exploit attempt).
2. First-time sudo success for a user (new privilege assignment).

ATT&CK: T1548 (Abuse of Elevation Control Mechanisms).
"""

from __future__ import annotations

from datetime import timedelta

from ..events import Event, Finding

SUDO_SUCCESS_TYPES = ("SUDO_SUCCESS",)
SUDO_FAILURE_TYPES = ("SUDO_FAILURE",)


class PrivilegeEscalation:
    name = "privilege_escalation"
    severity = "high"
    attack_id = "T1548"

    def run(self, events: list[Event], config: dict) -> list[Finding]:
        window = timedelta(
            minutes=config.get("window_minutes", 5)
        )

        # Group sudo events by username.
        sudo_by_user: dict[str, list[Event]] = {}
        for event in events:
            if event.event_type not in SUDO_SUCCESS_TYPES + SUDO_FAILURE_TYPES:
                continue
            user = event.username or "unknown"
            if user not in sudo_by_user:
                sudo_by_user[user] = []
            sudo_by_user[user].append(event)

        findings: list[Finding] = []
        users_flagged_first_success = set()

        for user, user_events in sudo_by_user.items():
            user_events.sort(key=lambda e: e.timestamp)

            failures = [
                e for e in user_events if e.event_type in SUDO_FAILURE_TYPES
            ]
            successes = [
                e for e in user_events if e.event_type in SUDO_SUCCESS_TYPES
            ]

            # Pattern 1: Successes preceded by failures within the window.
            for success in successes:
                preceding_failures = [
                    f
                    for f in failures
                    if success.timestamp - window <= f.timestamp < success.timestamp
                ]
                if preceding_failures:
                    findings.append(
                        Finding(
                            detection_name=self.name,
                            severity=self.severity,
                            timestamp=success.timestamp,
                            entities={"username": user},
                            evidence=[f.raw for f in preceding_failures]
                            + [success.raw],
                            attack_id=self.attack_id,
                            description=(
                                f"Sudo privilege escalation by '{user}': "
                                f"{len(preceding_failures)} failed attempt(s) within "
                                f"5 minutes, then successful escalation."
                            ),
                            false_positive_notes=(
                                "Legitimate users may mistype a password once. "
                                "Verify: Is this user authorized for sudo? "
                                "What command was escalated?"
                            ),
                        )
                    )

            # Pattern 2: First sudo success for a user.
            if successes and user not in users_flagged_first_success:
                first_success = successes[0]
                findings.append(
                    Finding(
                        detection_name=self.name,
                        severity="medium",
                        timestamp=first_success.timestamp,
                        entities={"username": user},
                        evidence=[first_success.raw],
                        attack_id=self.attack_id,
                        description=(
                            f"First sudo usage by '{user}' at {first_success.timestamp}. "
                            f"Indicates new or escalated privilege assignment."
                        ),
                        false_positive_notes=(
                            "Expected if the user's role changed or they're newly hired. "
                            "Verify: Is this user authorized to use sudo?"
                        ),
                    )
                )
                users_flagged_first_success.add(user)

        return findings