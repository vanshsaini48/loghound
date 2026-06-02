from datetime import datetime
from loghound.events import Finding
from loghound.triage.models import ScoredFinding
from loghound.reporting.markdown import generate_markdown_report


def _make_finding(detection_name="ssh_brute_force", severity="critical", **overrides):
    """Build a complete Finding; override any field per-test."""
    defaults = dict(
        detection_name=detection_name,
        severity=severity,
        timestamp=datetime(2026, 5, 31, 2, 15, 0),
        entities={"source_ip": "10.0.0.5", "username": "root"},
        evidence=["Failed password for root from 10.0.0.5"],
        attack_id="T1110",
        description="Multiple failed SSH logins from a single source IP.",
        false_positive_notes="Could be a misconfigured service retrying.",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_scored_finding(finding=None, **kwargs):
    """Wrap a Finding in ScoredFinding with optional overrides."""
    if finding is None:
        finding = _make_finding()
    return ScoredFinding(
        finding=finding,
        suppressed=kwargs.get("suppressed", False),
        suppression_reason=kwargs.get("suppression_reason"),
        ioc_hits=kwargs.get("ioc_hits", []),
        entity_risk=kwargs.get("entity_risk", {}),
    )


def test_report_renders_findings_with_severity_counts():
    scored_findings = [
        _make_scored_finding(_make_finding(severity="critical")),
        _make_scored_finding(
            _make_finding(detection_name="off_hours_login", severity="medium", attack_id="T1078")
        ),
    ]
    report = generate_markdown_report(scored_findings, source_file="auth.log", events_count=24)
    
    # Header + metadata
    assert "# Security Log Analysis Report" in report
    assert "auth.log" in report
    assert "Total Events Processed:** 24" in report
    
    # Executive summary count
    assert "detected 2 active finding(s)" in report
    
    # Severity table
    assert "| CRITICAL | 1 |" in report
    assert "| MEDIUM | 1 |" in report
    
    # Findings render by name, with entities, ATT&CK id, evidence, notes
    assert "ssh_brute_force" in report
    assert "off_hours_login" in report
    assert "source_ip: 10.0.0.5" in report
    assert "T1110" in report
    assert "Failed password for root" in report
    assert "## Analyst Notes" in report


def test_report_handles_empty_findings():
    report = generate_markdown_report([], source_file="clean.log", events_count=100)
    
    # A clean log still produces a complete, valid report
    assert "# Security Log Analysis Report" in report
    assert "detected 0 active finding(s)" in report
    assert "## Analyst Notes" in report
    
    # ...but no severity table or findings sections when there's nothing to show
    assert "| Severity | Count |" not in report


def test_report_shows_suppressed_findings():
    active = _make_scored_finding(_make_finding(severity="high"))
    suppressed = _make_scored_finding(
        _make_finding(severity="medium"),
        suppressed=True,
        suppression_reason="IP 10.0.0.5 is allowlisted",
    )
    
    report = generate_markdown_report([active, suppressed], source_file="auth.log", events_count=50)
    
    # Active count doesn't include suppressed
    assert "detected 1 active finding(s)" in report
    assert "(1 suppressed by allowlist)" in report
    
    # Suppressed section is shown
    assert "## Suppressed Findings" in report
    assert "IP 10.0.0.5 is allowlisted" in report


def test_report_shows_entity_risk_scores():
    scored_finding = _make_scored_finding(
        _make_finding(),
        entity_risk={"source_ip:10.0.0.5": 4, "username:root": 2},
    )
    
    report = generate_markdown_report([scored_finding], source_file="auth.log", events_count=100)
    
    # Risk scores should appear in detailed findings
    assert "risk: 4" in report
    assert "risk: 2" in report
    
    # Risk should appear in summary table
    assert "| Risk |" in report
