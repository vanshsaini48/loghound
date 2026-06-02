"""FR-3.6 — Privilege Escalation Indicators (streaming).

Two patterns, both streaming:
1. Sudo success preceded by failures within a 5-minute window.
2. First-time sudo success for a user in the stream.

State: per-user deque of recent failures + set of users seen.

ATT&CK: T1548 (Abuse of Elevation Control Mechanisms).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable, Optional

from ..events import Event, Finding

SUDO_SUCCESS_TYPES = ("SUDO_SUCCESS",)
SUDO_FAILURE_TYPES = ("SUDO_FAILURE",)


class PrivilegeEscalation:
    name = "privilege_escalation"
    severity = "high"
    attack_id: Optional[str] = "T1548"

    def __init__(self, config: dict) -> None:
        self._window = timedelta(minutes=config.get("window_minutes", 5))
        self._failures: dict[str, deque] = defaultdict(deque)
        self._first_success_seen: set[str] = set()

    def process(self, event: Event) -> Iterable[Finding]:
        if event.event_type not in SUDO_SUCCESS_TYPES + SUDO_FAILURE_TYPES:
            return

        user = event.username or "unknown"

        if event.event_type in SUDO_FAILURE_TYPES:
            dq = self._failures[user]
            dq.append(event)
            # Evict outside window
            cutoff = event.timestamp - self._window
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()
            return

        # --- SUDO_SUCCESS ---
        # Pattern 1: preceded by failures within window
        dq = self._failures.get(user, deque())
        cutoff = event.timestamp - self._window
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()

        if dq:
            preceding = list(dq)
            yield Finding(
                detection_name=self.name,
                severity=self.severity,
                timestamp=event.timestamp,
                entities={"username": user},
                evidence=[f.raw for f in preceding] + [event.raw],
                attack_id=self.attack_id,
                description=(
                    f"Sudo privilege escalation by '{user}': "
                    f"{len(preceding)} failed attempt(s) within "
                    f"5 minutes, then successful escalation."
                ),
                false_positive_notes=(
                    "Legitimate users may mistype a password once. "
                    "Verify: Is this user authorized for sudo? "
                    "What command was escalated?"
                ),
            )

        # Pattern 2: first sudo success for this user
        if user not in self._first_success_seen:
            self._first_success_seen.add(user)
            yield Finding(
                detection_name=self.name,
                severity="medium",
                timestamp=event.timestamp,
                entities={"username": user},
                evidence=[event.raw],
                attack_id=self.attack_id,
                description=(
                    f"First sudo usage by '{user}' at {event.timestamp}. "
                    f"Indicates new or escalated privilege assignment."
                ),
                false_positive_notes=(
                    "Expected if the user's role changed or they're newly hired. "
                    "Verify: Is this user authorized to use sudo?"
                ),
            )

    def finalize(self) -> Iterable[Finding]:
        return ()
