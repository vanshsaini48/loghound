"""FR-3.7 — Password Spraying detection (streaming).

One source IP attempting failed logins across many distinct usernames
within a sliding window. The inverse of brute force: few attempts per
user, many users.

ATT&CK: T1110.003 (Password Spraying).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable, Optional

from ..events import Event, Finding


class PasswordSpraying:
    name = "password_spraying"
    severity = "high"
    attack_id: Optional[str] = "T1110.003"

    def __init__(self, config: dict) -> None:
        self._distinct_users = config.get("distinct_users", 10)
        self._window = timedelta(minutes=config.get("window_minutes", 15))
        self._attempts: dict[str, deque] = defaultdict(deque)
        self._flagged: set[str] = set()

    def _evict(self, ip: str, cutoff) -> None:
        """Remove entries older than the window cutoff."""
        dq = self._attempts[ip]
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def process(self, event: Event) -> Iterable[Finding]:
        if (event.fields.get("process") != "sshd"
                or "Failed password" not in event.fields.get("message", "")
                or event.source_ip is None
                or event.username is None):
            return

        ip = event.source_ip
        if ip in self._flagged:
            return

        dq = self._attempts[ip]
        dq.append((event.timestamp, event.username))

        self._evict(ip, event.timestamp - self._window)

        distinct = {username for _, username in dq}
        if len(distinct) >= self._distinct_users:
            self._flagged.add(ip)
            evidence = [f"{ts} -> {user}" for ts, user in list(dq)]
            window_min = int(self._window.total_seconds() // 60)
            yield Finding(
                detection_name=self.name,
                severity=self.severity,
                timestamp=dq[0][0],
                entities={"source_ip": ip},
                evidence=evidence,
                attack_id=self.attack_id,
                description=(
                    f"Password spraying from {ip}: failed logins against "
                    f"{len(distinct)} distinct usernames in {window_min} "
                    f"minutes"
                ),
                false_positive_notes=(
                    "Could be a shared jump host or NAT gateway where "
                    "multiple users fail authentication from the same IP. "
                    "Check whether the IP is a known proxy or VPN endpoint."
                ),
            )
            del self._attempts[ip]

    def finalize(self) -> Iterable[Finding]:
        return ()
