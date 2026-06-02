"""FR-3.5 — Suspicious User-Agent detection (streaming).

Flags HTTP requests with scanner user-agents or CLI clients without referrer.
Stateless per-event: emits immediately on match.
The triage layer (Phase 2) aggregates repeated hits per IP.

ATT&CK: T1595 (Active Scanning).
"""

from __future__ import annotations

from typing import Iterable, Optional

from ..events import Event, Finding

SCANNER_SIGNATURES = (
    "sqlmap", "nikto", "nmap", "masscan", "gobuster",
    "ffuf", "dirb", "wpscan", "nuclei", "hydra",
)
CLI_CLIENTS = ("curl", "wget")


class SuspiciousUserAgent:
    name = "suspicious_user_agent"
    severity = "medium"
    attack_id: Optional[str] = "T1595"

    def __init__(self, config: dict) -> None:
        self._signatures = tuple(
            s.lower() for s in config.get("signatures", SCANNER_SIGNATURES)
        )

    def process(self, event: Event) -> Iterable[Finding]:
        if event.event_type != "HTTP_REQUEST":
            return
        ua = event.fields.get("user_agent", "").lower()
        if not ua:
            return

        hit = next((s for s in self._signatures if s in ua), None)
        if hit is None and any(c in ua for c in CLI_CLIENTS):
            if not event.fields.get("referer"):
                hit = "cli-client-no-referer"

        if hit is None:
            return

        ip = event.source_ip or "unknown"
        yield Finding(
            detection_name=self.name,
            severity=self.severity,
            timestamp=event.timestamp,
            entities={"source_ip": ip},
            evidence=[event.raw],
            attack_id=self.attack_id,
            description=f"{ip} sent request with suspicious user-agent: {hit}.",
            false_positive_notes=(
                "Internal vuln scans, uptime monitors, and legitimate "
                "cron+curl automation can match. Confirm the source IP "
                "is not an authorized scanner."
            ),
        )

    def finalize(self) -> Iterable[Finding]:
        return ()
