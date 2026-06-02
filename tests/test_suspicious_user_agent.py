"""Tests for FR-3.5 — Suspicious User-Agent detection (streaming contract)."""
from datetime import datetime
from loghound.events import Event
from loghound.detections.suspicious_user_agent import SuspiciousUserAgent


def _run_streaming(det, events):
    """Helper: drive a streaming detection over a list of events."""
    findings = []
    for event in events:
        findings.extend(det.process(event))
    findings.extend(det.finalize())
    return findings


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


def test_flags_scanner_user_agent(test_config):
    config = test_config["detections"]["suspicious_user_agent"]
    findings = _run_streaming(SuspiciousUserAgent(config), [make_event("sqlmap/1.5.12#stable")])
    assert len(findings) == 1
    assert findings[0].entities["source_ip"] == "10.0.0.9"
    assert findings[0].attack_id == "T1595"


def test_ignores_normal_browser(test_config):
    config = test_config["detections"]["suspicious_user_agent"]
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0"
    assert _run_streaming(SuspiciousUserAgent(config), [make_event(ua)]) == []


def test_curl_without_referer_is_flagged(test_config):
    config = test_config["detections"]["suspicious_user_agent"]
    assert len(_run_streaming(SuspiciousUserAgent(config), [make_event("curl/8.4.0")])) == 1


def test_curl_with_referer_is_ignored(test_config):
    config = test_config["detections"]["suspicious_user_agent"]
    events = [make_event("curl/8.4.0", referer="https://example.com/")]
    assert _run_streaming(SuspiciousUserAgent(config), events) == []
