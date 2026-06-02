"""FR-3.2 — Successful Login After Brute Force (streaming).

Tracks failed SSH logins per IP in a lookback window. When a success
arrives from an IP with >= threshold prior failures, emits a finding.
State: per-IP deque of failures + flagged set.

ATT&CK: T1110 (Brute Force).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable, Optional

from ..events import Event, Finding


class SuccessfulAfterBrute:
    name = "successful_after_brute"
    severity = "critical"
    attack_id: Optional[str] = "T1110"

    def __init__(self, config: dict) -> None:
        self._threshold = config.get("threshold", 5)
        self._lookback = timedelta(
            minutes=config.get("lookback_minutes", 60)
        )
        self._failures: dict[str, deque] = defaultdict(deque)
        self._flagged: set[str] = set()

    def process(self, event: Event) -> Iterable[Finding]:
        if event.fields.get("process") != "sshd" or event.source_ip is None:
            return

        ip = event.source_ip
        msg = event.fields.get("message", "")

        if "Failed password" in msg:
            dq = self._failures[ip]
            dq.append(event)
            # Evict outside lookback window
            cutoff = event.timestamp - self._lookback
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()
            return

        if "Accepted password" in msg:
            if ip in self._flagged:
                return

            dq = self._failures.get(ip, deque())
            cutoff = event.timestamp - self._lookback
            while dq and dq[0].timestamp < cutoff:
                dq.popleft()

            if len(dq) >= self._threshold:
                self._flagged.add(ip)
                prior = list(dq)
                lookback_min = int(self._lookback.total_seconds() // 60)
                yield Finding(
                    detection_name=self.name,
                    severity=self.severity,
                    timestamp=event.timestamp,
                    entities={"source_ip": ip},
                    evidence=[e.raw for e in prior[:self._threshold]]
                    + [event.raw],
                    attack_id=self.attack_id,
                    description=(
                        f"Successful SSH login from {ip} after "
                        f"{len(prior)} failed attempts in the previous "
                        f"{lookback_min} minutes \u2014 possible successful "
                        f"brute force"
                    ),
                    false_positive_notes=(
                        "A user who forgot their password, retried several "
                        "times, then succeeded could trigger this. Risk is "
                        "higher when the failures span multiple usernames or "
                        "come from an unfamiliar IP."
                    ),
                )

    def finalize(self) -> Iterable[Finding]:
        return ()
