from pathlib import Path
from loghound.parsers.syslog import parse_file
from loghound.engine import run_engine

def test_engine_runs_all_detections(test_config):
    """Integration test: engine runs all detections and sorts findings."""
    events = list(parse_file(Path('tests/fixtures/sample_auth.log')))
    
    findings = run_engine(events, test_config)
    
    # Should find:
    # - 1 SSH brute force (203.0.113.42)
    # - 1 successful after brute (203.0.113.42)
    # - 1 privilege escalation (jdoe first sudo)
    # - 1 new IP for user (jdoe from attacker IP after known IP)
    # - 0 off-hours logins (all successes are within 08:00-19:00)
    assert len(findings) == 4
    
    # First finding should be "successful_after_brute" (critical > high)
    assert findings[0].detection_name == "successful_after_brute"
    assert findings[0].severity == "critical"
    
    # Second finding should be "ssh_brute_force" (high)
    assert findings[1].detection_name == "ssh_brute_force"
    assert findings[1].severity == "high"
