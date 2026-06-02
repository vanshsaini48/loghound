import pytest
from datetime import datetime, timedelta

from loghound.events import Event
from loghound.detections.web_recon import WebRecon


def _run_streaming(det, events):
    findings = []
    for event in events:
        findings.extend(det.process(event))
    findings.extend(det.finalize())
    return findings


@pytest.fixture
def synthetic_scanner_events():
    """Simulate 60 requests from one IP, all within 5 minutes, 80% 4xx."""
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    events = []
    for i in range(60):
        status = "404" if i % 5 < 4 else "200"
        event = Event(
            timestamp=base_time + timedelta(seconds=i * 5),
            source="apache",
            event_type="HTTP_REQUEST",
            source_ip="192.168.1.100",
            username=None,
            raw=f'192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /api/v{i % 3}/users HTTP/1.1" {status} 0 "-" "gobuster/3.0"',
            fields={
                "http_path": f"/api/v{i % 3}/users",
                "http_status": status,
                "http_user_agent": "gobuster/3.0",
            }
        )
        events.append(event)
    return events


@pytest.fixture
def synthetic_legitimate_traffic():
    """Legitimate web traffic: few requests, mostly 200s."""
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    events = []
    for i in range(20):
        event = Event(
            timestamp=base_time + timedelta(seconds=i * 10),
            source="apache",
            event_type="HTTP_REQUEST",
            source_ip="192.168.1.200",
            username=None,
            raw=f'192.168.1.200 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
            fields={
                "http_path": "/index.html",
                "http_status": "200",
                "http_user_agent": "Mozilla/5.0",
            }
        )
        events.append(event)
    return events


@pytest.fixture
def synthetic_below_threshold():
    """40 requests (below 50 threshold) with 80% 4xx."""
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    events = []
    for i in range(40):
        status = "404" if i % 5 < 4 else "200"
        event = Event(
            timestamp=base_time + timedelta(seconds=i * 7),
            source="apache",
            event_type="HTTP_REQUEST",
            source_ip="192.168.1.150",
            username=None,
            raw=f'192.168.1.150 - - [01/Jan/2024:12:00:00 +0000] "GET /path{i} HTTP/1.1" {status} 0 "-" "curl/7.64.1"',
            fields={
                "http_path": f"/path{i}",
                "http_status": status,
                "http_user_agent": "curl/7.64.1",
            }
        )
        events.append(event)
    return events


def test_detects_scanner_behavior(synthetic_scanner_events, test_config):
    """Positive: 60 requests, 80% 4xx within 5 min -> finding."""
    config = test_config["detections"]["web_recon"]
    det = WebRecon(config)
    findings = _run_streaming(det, synthetic_scanner_events)

    assert len(findings) == 1, "Should find exactly one scanner"
    assert findings[0].detection_name == "web_recon"
    assert findings[0].severity == "high"
    assert findings[0].attack_id == "T1190"
    assert findings[0].entities["source_ip"] == "192.168.1.100"
    assert "gobuster" in findings[0].description.lower()
    assert len(findings[0].evidence) > 0


def test_skips_legitimate_traffic(synthetic_legitimate_traffic, test_config):
    """Negative: 20 requests, high success rate -> no finding."""
    config = test_config["detections"]["web_recon"]
    det = WebRecon(config)
    findings = _run_streaming(det, synthetic_legitimate_traffic)

    assert len(findings) == 0, "Should not flag legitimate traffic"


def test_respects_request_threshold(synthetic_below_threshold, test_config):
    """Negative: 40 requests (below 50 threshold) -> no finding."""
    config = test_config["detections"]["web_recon"]
    det = WebRecon(config)
    findings = _run_streaming(det, synthetic_below_threshold)

    assert len(findings) == 0, "Should not flag when below threshold"
