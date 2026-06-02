"""FR-3.4 — Web Reconnaissance detection (streaming).

Sliding window per source IP: emits when request count hits the
threshold AND the 4xx error rate exceeds the configured ratio.
State is one deque per active IP, evicted by time.

ATT&CK: T1190 (Exploit Public-Facing Application).
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable, Optional

from ..events import Event, Finding


class WebRecon:
    name = "web_recon"
    severity = "high"
    attack_id: Optional[str] = "T1190"

    def __init__(self, config: dict) -> None:
        self._threshold = config.get("threshold", 50)
        self._window = timedelta(minutes=config.get("window_minutes", 5))
        self._error_rate_threshold = config.get("error_rate_threshold", 0.6)
        self._requests: dict[str, deque] = defaultdict(deque)
        self._flagged: set[str] = set()

    def process(self, event: Event) -> Iterable[Finding]:
        if event.event_type != "HTTP_REQUEST":
            return
        ip = event.source_ip
        if not ip or ip in self._flagged:
            return

        dq = self._requests[ip]
        dq.append(event)

        # Evict events outside the window
        cutoff = event.timestamp - self._window
        while dq and dq[0].timestamp < cutoff:
            dq.popleft()

        if len(dq) < self._threshold:
            return

        # Check error rate
        errors = sum(
            1 for e in dq
            if e.fields.get("http_status", "").startswith("4")
        )
        error_rate = errors / len(dq)

        if error_rate < self._error_rate_threshold:
            return

        self._flagged.add(ip)
        window_events = list(dq)
        scanner_ua = self._extract_scanner_ua(window_events)
        window_min = int(self._window.total_seconds() // 60)

        yield Finding(
            detection_name=self.name,
            severity=self.severity,
            timestamp=window_events[0].timestamp,
            entities={
                "source_ip": ip,
                "request_count": str(len(window_events)),
                "error_rate": f"{error_rate:.0%}",
                "window_minutes": str(window_min),
            },
            evidence=[
                f"{e.source_ip} -> {e.fields.get('http_path', '?')} "
                f"HTTP {e.fields.get('http_status', '?')}"
                for e in window_events[:5]
            ],
            attack_id=self.attack_id,
            description=(
                f"Web scanner detected: {ip} made {len(window_events)} requests "
                f"in {window_min} minutes, {error_rate:.0%} returned 4xx (404 Not Found). "
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
        del self._requests[ip]

    def finalize(self) -> Iterable[Finding]:
        return ()

    @staticmethod
    def _extract_scanner_ua(events: list) -> str | None:
        known = ("sqlmap", "nikto", "nmap", "masscan", "gobuster", "ffuf")
        found = set()
        for event in events:
            ua = event.fields.get("http_user_agent", "").lower()
            for s in known:
                if s in ua:
                    found.add(s)
        return ", ".join(sorted(found)) if found else None
