"""FR-3.1 — SSH Brute Force detection (streaming).

Sliding window per source IP: emits when failure count in the window
reaches the threshold. State is bounded — one deque per active IP,
evicted as events age out.

ATT&CK: T1110 (Brute Force).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable, Optional

from ..events import Event, Finding


class SSHBruteForce:
    name = "ssh_brute_force"
    severity = "high"
    attack_id: Optional[str] = "T1110"

    def __init__(self, config: dict) -> None:
        self._threshold = config.get("threshold", 5)
        self._window = timedelta(minutes=config.get("window_minutes", 10))
        self._failures: dict[str, deque] = defaultdict(deque)
        self._flagged: set[str] = set()

    def process(self, event: Event) -> Iterable[Finding]:
        if (event.fields.get("process") != "sshd"
                or "Failed password" not in event.fields.get("message", "")
                or event.source_ip is None):
            return

        ip = event.source_ip
        if ip in self._flagged:
            return

        dq = self._failures[ip]
        dq.append(event)

        # Evict events outside the window
        cutoff = event.timestamp - self._window
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()

        if len(dq) >= self._threshold:
            self._flagged.add(ip)
            evidence = [e.raw for e in list(dq)[:self._threshold]]
            window_min = int(self._window.total_seconds() // 60)
            yield Finding(
                detection_name=self.name,
                severity=self.severity,
                timestamp=dq[0].timestamp,
                entities={"source_ip": ip},
                evidence=evidence,
                attack_id=self.attack_id,
                description=(
                    f"SSH brute force from {ip}: {len(dq)} failed login "
                    f"attempts in {window_min} minutes"
                ),
                false_positive_notes=(
                    "Could be a legitimate user repeatedly typing their "
                    "password wrong, but 5+ attempts across multiple accounts "
                    "within 10 minutes is rare and suspicious."
                ),
            )
            del self._failures[ip]

    def finalize(self) -> Iterable[Finding]:
        return ()
