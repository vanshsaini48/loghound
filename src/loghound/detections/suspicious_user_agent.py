"""FR-3.5 — Suspicious User-Agent detection.

Flags HTTP requests whose User-Agent matches known scanning tools, or
command-line clients (curl/wget) used without a Referer — a common
signature of scripted, non-browser access.

ATT&CK: T1595 (Active Scanning).
"""

from __future__ import annotations

from collections import defaultdict

from ..events import Event, Finding

SCANNER_SIGNATURES = (
    "sqlmap", "nikto", "nmap", "masscan", "gobuster",
    "ffuf", "dirb", "wpscan", "nuclei", "hydra",
)
CLI_CLIENTS = ("curl", "wget")


class SuspiciousUserAgent:
    name = "suspicious_user_agent"
    severity = "medium"
    attack_id = "T1595"

    def run(self, events: list[Event], config: dict) -> list[Finding]:
        signatures = tuple(
            s.lower() for s in config.get("signatures", SCANNER_SIGNATURES)
        )
        matches: dict[str, list[tuple[Event, str]]] = defaultdict(list)

        for event in events:
            if event.event_type != "HTTP_REQUEST":
                continue
            ua = event.fields.get("user_agent", "").lower()
            if not ua:
                continue

            hit = next((s for s in signatures if s in ua), None)
            if hit is None and any(c in ua for c in CLI_CLIENTS):
                if not event.fields.get("referer"):
                    hit = "cli-client-no-referer"

            if hit is not None:
                matches[event.source_ip or "unknown"].append((event, hit))

        findings: list[Finding] = []
        for ip, hits in matches.items():
            tools = sorted({label for _, label in hits})
            findings.append(
                Finding(
                    detection_name=self.name,
                    severity=self.severity,
                    timestamp=hits[0][0].timestamp,
                    entities={"source_ip": ip},
                    evidence=[e.raw for e, _ in hits[:10]],
                    attack_id=self.attack_id,
                    description=(
                        f"{ip} sent {len(hits)} request(s) with suspicious "
                        f"user-agent(s): {', '.join(tools)}."
                    ),
                    false_positive_notes=(
                        "Internal vuln scans, uptime monitors, and legitimate "
                        "cron+curl automation can match. Confirm the source IP "
                        "is not an authorized scanner."
                    ),
                )
            )
        return findings