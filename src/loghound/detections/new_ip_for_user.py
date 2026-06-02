"""FR-3.8 — New Source IP for User detection (streaming).

A successful login for a user from an IP never previously seen for
that user in the stream. Useful for spotting compromised credentials
used from attacker infrastructure.

ATT&CK: T1078 (Valid Accounts).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from ..events import Event, Finding


class NewIPForUser:
    name = "new_ip_for_user"
    severity = "low"
    attack_id: Optional[str] = "T1078"

    def __init__(self, config: dict) -> None:
        # Per-user: set of IPs seen so far
        self._seen_ips: dict[str, set[str]] = defaultdict(set)

    def process(self, event: Event) -> Iterable[Finding]:
        # Only successful SSH logins
        if (event.fields.get("process") != "sshd"
                or "Accepted" not in event.fields.get("message", "")
                or event.source_ip is None
                or event.username is None):
            return

        user = event.username
        ip = event.source_ip
        known = self._seen_ips[user]

        if ip not in known:
            # First appearance is expected (no finding for truly first login)
            if known:
                yield Finding(
                    detection_name=self.name,
                    severity=self.severity,
                    timestamp=event.timestamp,
                    entities={"username": user, "source_ip": ip},
                    evidence=[event.raw],
                    attack_id=self.attack_id,
                    description=(
                        f"User '{user}' logged in from new IP {ip} "
                        f"(previously seen from: "
                        f"{', '.join(sorted(known))})"
                    ),
                    false_positive_notes=(
                        "Expected when users switch networks (home, office, "
                        "VPN). Suspicious if the new IP is in an unexpected "
                        "geography or ASN."
                    ),
                )
            known.add(ip)

    def finalize(self) -> Iterable[Finding]:
        return ()
