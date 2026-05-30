from datetime import datetime

from loghound.events import Finding
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


def test_report_renders_findings_with_severity_counts():
    findings = [
        _make_finding(severity="critical"),
        _make_finding(detection_name="off_hours_login", severity="medium", attack_id="T1078"),
    ]
    report = generate_markdown_report(findings, source_file="auth.log", events_count=24)

    # Header + metadata
    assert "# Security Log Analysis Report" in report
    assert "auth.log" in report
    assert "Total Events Processed:** 24" in report

    # Executive summary count
    assert "detected 2 security finding(s)" in report

    # Severity table — this is the exact Day 13 bug, now locked in
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
    assert "detected 0 security finding(s)" in report
    assert "## Analyst Notes" in report

    # ...but no severity table or findings sections when there's nothing to show
    assert "| Severity | Count |" not in report
    assert "## Detailed Findings" not in report
