"""FR-3.3 — Off-Hours Authentication (streaming).

Flags successful SSH logins outside configurable business hours.
Stateless: each event is evaluated independently.

ATT&CK: T1078 (Valid Accounts).
"""

from __future__ import annotations

from datetime import time
from typing import Iterable, Optional

from ..events import Event, Finding


class OffHoursLogin:
    name = "off_hours_login"
    severity = "medium"
    attack_id: Optional[str] = "T1078"

    def __init__(self, config: dict) -> None:
        bh = config.get("business_hours", {})
        self._start_str = bh.get("start", "08:00")
        self._end_str = bh.get("end", "19:00")
        self._start = self._parse_time(self._start_str)
        self._end = self._parse_time(self._end_str)

    def process(self, event: Event) -> Iterable[Finding]:
        if (event.fields.get("process") != "sshd"
                or "Accepted password" not in event.fields.get("message", "")
                or event.source_ip is None):
            return

        event_time = event.timestamp.time()
        if not (self._start <= event_time < self._end):
            yield Finding(
                detection_name=self.name,
                severity=self.severity,
                timestamp=event.timestamp,
                entities={"username": event.username or "unknown",
                          "source_ip": event.source_ip},
                evidence=[event.raw],
                attack_id=self.attack_id,
                description=(
                    f"SSH login from {event.source_ip} outside business hours "
                    f"({self._start_str}\u2013{self._end_str})"
                ),
                false_positive_notes=(
                    "Off-hours logins can be legitimate for on-call staff, "
                    "developers in different timezones, or automated processes. "
                    "Cross-reference with known on-call schedules."
                ),
            )

    def finalize(self) -> Iterable[Finding]:
        return ()

    @staticmethod
    def _parse_time(time_str: str) -> time:
        h, m = map(int, time_str.split(":"))
        return time(h, m)
