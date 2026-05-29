import pytest
from datetime import datetime, timedelta

from loghound.events import Event
from loghound.detections.web_recon import WebRecon


@pytest.fixture
def web_recon_detector():
    return WebRecon()


@pytest.fixture
def synthetic_scanner_events():
    """Simulate 60 requests from one IP, all within 5 minutes, 80% 4xx.
    
    This mimics what gobuster/nikto/nmap would do: rapid enumeration
    hitting many non-existent endpoints (404s).
    """
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    events = []
    
    for i in range(60):
        # Pattern: 4 out of 5 requests return 404 (80% error rate)
        status = "404" if i % 5 < 4 else "200"
        
        event = Event(
            timestamp=base_time + timedelta(seconds=i * 5),  # Spread over 5 min
            source="apache",
            event_type="HTTP_REQUEST",
            source_ip="192.168.1.100",
            username=None,
            raw=f'192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] '
                f'"GET /api/v{i % 3}/users HTTP/1.1" {status} 0 "-" "gobuster/3.0"',
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
            raw=f'192.168.1.200 - - [01/Jan/2024:12:00:00 +0000] '
                f'"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
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
            raw=f'192.168.1.150 - - [01/Jan/2024:12:00:00 +0000] '
                f'"GET /path{i} HTTP/1.1" {status} 0 "-" "curl/7.64.1"',
            fields={
                "http_path": f"/path{i}",
                "http_status": status,
                "http_user_agent": "curl/7.64.1",
            }
        )
        events.append(event)
    
    return events


def test_detects_scanner_behavior(web_recon_detector, synthetic_scanner_events):
    """Positive: 60 requests, 80% 4xx within 5 min → finding."""
    config = {
        "threshold": 50,
        "window_minutes": 5,
        "error_rate_threshold": 0.6,
    }
    
    findings = web_recon_detector.run(synthetic_scanner_events, config)
    
    assert len(findings) == 1, "Should find exactly one scanner"
    assert findings[0].detection_name == "web_recon"
    assert findings[0].severity == "high"
    assert findings[0].attack_id == "T1190"
    assert findings[0].entities["source_ip"] == "192.168.1.100"
    assert "gobuster" in findings[0].description.lower()
    assert len(findings[0].evidence) > 0


def test_skips_legitimate_traffic(web_recon_detector, synthetic_legitimate_traffic):
    """Negative: 20 requests, high success rate → no finding."""
    config = {
        "threshold": 50,
        "window_minutes": 5,
        "error_rate_threshold": 0.6,
    }
    
    findings = web_recon_detector.run(synthetic_legitimate_traffic, config)
    
    assert len(findings) == 0, "Should not flag legitimate traffic"


def test_respects_request_threshold(web_recon_detector, synthetic_below_threshold):
    """Negative: 40 requests (below 50 threshold) → no finding."""
    config = {
        "threshold": 50,
        "window_minutes": 5,
        "error_rate_threshold": 0.6,
    }
    
    findings = web_recon_detector.run(synthetic_below_threshold, config)
    
    assert len(findings) == 0, "Should not flag when below threshold"