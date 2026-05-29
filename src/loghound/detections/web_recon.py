from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from ..events import Event, Finding


@dataclass
class WebRecon:
    """Detects web scanner behavior (T1190 — Exploit Public-Facing Application).
    
    Pattern: Single IP, 50+ requests, 60%+ 4xx responses, within 5-minute window.
    Indicates systematic enumeration/probing (gobuster, nikto, nmap -sV, etc.).
    
    Severity: high
    """

    name = "web_recon"
    severity = "high"
    attack_id = "T1190"

    def run(self, events: list[Event], config: dict) -> list[Finding]:
        """Analyze events for scanner behavior."""
        
        # Extract config with sensible defaults
        threshold = config.get("threshold", 50)
        window_minutes = config.get("window_minutes", 5)
        error_rate_threshold = config.get("error_rate_threshold", 0.6)

        findings = []

        # Group events by source IP (only HTTP_REQUEST events)
        events_by_ip = {}
        for event in events:
            if event.event_type != "HTTP_REQUEST":
                continue
            
            ip = event.source_ip
            if not ip:
                continue
            
            if ip not in events_by_ip:
                events_by_ip[ip] = []
            events_by_ip[ip].append(event)

        # Analyze each IP for scanner patterns
        for ip, ip_events in events_by_ip.items():
            if len(ip_events) < threshold:
                # Too few requests, skip
                continue

            # Look for a 5-minute window with 50+ requests
            for start_event in ip_events:
                window_end = start_event.timestamp + timedelta(minutes=window_minutes)
                window_events = [
                    e for e in ip_events
                    if start_event.timestamp <= e.timestamp <= window_end
                ]

                if len(window_events) < threshold:
                    continue

                # Check error rate in this window
                error_responses = [
                    e for e in window_events
                    if "http_status" in e.fields
                    and e.fields["http_status"].startswith("4")
                ]

                error_rate = len(error_responses) / len(window_events)
                if error_rate < error_rate_threshold:
                    continue

                # ✅ Found a scanner! Create finding.
                scanner_ua = self._extract_scanner_ua(window_events)
                
                finding = Finding(
                    detection_name=self.name,
                    severity=self.severity,
                    timestamp=start_event.timestamp,
                    entities={
                        "source_ip": ip,
                        "request_count": str(len(window_events)),
                        "error_rate": f"{error_rate:.0%}",
                        "window_minutes": str(window_minutes),
                    },
                    evidence=[
                        f"{e.source_ip} -> {e.fields.get('http_path', '?')} "
                        f"HTTP {e.fields.get('http_status', '?')}"
                        for e in window_events[:5]  # First 5 requests
                    ],
                    attack_id=self.attack_id,
                    description=(
                        f"Web scanner detected: {ip} made {len(window_events)} requests "
                        f"in {window_minutes} minutes, {error_rate:.0%} returned 4xx (404 Not Found). "
                        f"Pattern matches automated enumeration tools. "
                        f"Scanner signatures: {scanner_ua if scanner_ua else 'none detected (generic scan)'}."
                    ),
                    false_positive_notes=(
                        "Legitimate tools (curl, wget, test frameworks) can trigger if "
                        "misconfigured to retry failed endpoints. Check User-Agent header. "
                        "Dev/test environments with active debugging often see this pattern. "
                        "Correlate with legitimate development activity before escalating."
                    ),
                )
                findings.append(finding)
                break  # One finding per IP (no duplicate findings in same window)

        return findings

    def _extract_scanner_ua(self, events: list[Event]) -> str:
        """Pull out known scanner signatures from User-Agent headers."""
        known_scanners = ["sqlmap", "nikto", "nmap", "masscan", "gobuster", "ffuf"]
        found = set()
        
        for event in events:
            ua = event.fields.get("http_user_agent", "").lower()
            for scanner in known_scanners:
                if scanner in ua:
                    found.add(scanner)
        
        return ", ".join(sorted(found)) if found else None