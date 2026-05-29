from pathlib import Path
from src.loghound.parsers.syslog import parse_file
from src.loghound.engine import run_engine

def test_engine_runs_all_detections():
    """Integration test: engine runs all three detections and sorts findings."""
    events = list(parse_file(Path('tests/fixtures/sample_auth.log')))
    
    config = {
        "detections": {
            "ssh_brute_force": {"enabled": True, "threshold": 5, "window_minutes": 10},
            "successful_after_brute": {"enabled": True, "threshold": 5, "lookback_minutes": 60},
            "off_hours_login": {"enabled": True, "business_hours": {"start": "08:00", "end": "19:00"}},
        }
    }
    
    findings = run_engine(events, config)
    
    # Should find:
    # - 1 SSH brute force (203.0.113.42)
    # - 1 successful after brute (203.0.113.42)
    # - 0 off-hours logins (all successes are within 08:00-19:00)
    assert len(findings) == 2
    
    # First finding should be "successful_after_brute" (critical > high)
    assert findings[0].detection_name == "successful_after_brute"
    assert findings[0].severity == "critical"
    
    # Second finding should be "ssh_brute_force" (high)
    assert findings[1].detection_name == "ssh_brute_force"
    assert findings[1].severity == "high"
