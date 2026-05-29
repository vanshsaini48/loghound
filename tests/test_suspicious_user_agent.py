"""Tests for FR-3.5 — Suspicious User-Agent detection."""

from datetime import datetime

from loghound.events import Event
from loghound.detections.suspicious_user_agent import SuspiciousUserAgent


def make_event(user_agent: str, ip: str = "10.0.0.9", referer: str = "") -> Event:
    fields = {"user_agent": user_agent}
    if referer:
        fields["referer"] = referer
    return Event(
        timestamp=datetime(2026, 5, 30, 12, 0, 0),
        source="access.log",
        event_type="HTTP_REQUEST",
        source_ip=ip,
        username=None,
        raw=f'{ip} - - "GET /admin" 404 "{user_agent}"',
        fields=fields,
    )


def test_flags_scanner_user_agent():
    findings = SuspiciousUserAgent().run([make_event("sqlmap/1.5.12#stable")], {})
    assert len(findings) == 1
    assert findings[0].entities["source_ip"] == "10.0.0.9"
    assert findings[0].attack_id == "T1595"


def test_ignores_normal_browser():
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0"
    assert SuspiciousUserAgent().run([make_event(ua)], {}) == []


def test_curl_without_referer_is_flagged():
    assert len(SuspiciousUserAgent().run([make_event("curl/8.4.0")], {})) == 1


def test_curl_with_referer_is_ignored():
    events = [make_event("curl/8.4.0", referer="https://example.com/")]
    assert SuspiciousUserAgent().run(events, {}) == []