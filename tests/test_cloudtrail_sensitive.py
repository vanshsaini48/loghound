"""Tests for FR-3.9 — CloudTrail Sensitive Actions detection (streaming contract)."""

from datetime import datetime, timezone
from pathlib import Path

from loghound.events import Event
from loghound.parsers import cloudtrail
from loghound.detections.cloudtrail_sensitive import CloudTrailSensitive

FIXTURE = Path(__file__).parent / "fixtures" / "sample_cloudtrail.json"


def _run_streaming(det, events):
    findings = []
    for event in events:
        findings.extend(det.process(event))
    findings.extend(det.finalize())
    return findings


def test_detects_console_login_without_mfa(test_config):
    """Positive: ConsoleLogin with mfa_authenticated=false."""
    events = list(cloudtrail.parse_file(FIXTURE))
    config = test_config["detections"]["cloudtrail_sensitive"]
    det = CloudTrailSensitive(config)
    findings = _run_streaming(det, events)

    mfa_findings = [f for f in findings if "ConsoleLogin" in f.description]
    assert len(mfa_findings) == 1
    assert mfa_findings[0].attack_id == "T1078.004"
    assert "mallory" in mfa_findings[0].description


def test_does_not_flag_console_login_with_mfa(test_config):
    """Negative: ConsoleLogin with MFA is not flagged."""
    events = list(cloudtrail.parse_file(FIXTURE))
    config = test_config["detections"]["cloudtrail_sensitive"]
    det = CloudTrailSensitive(config)
    findings = _run_streaming(det, events)

    # alice logged in with MFA — should not appear in findings
    alice_logins = [f for f in findings if "alice" in f.description and "ConsoleLogin" in f.description]
    assert len(alice_logins) == 0


def test_detects_create_access_key(test_config):
    """Positive: CreateAccessKey is a sensitive IAM action."""
    events = list(cloudtrail.parse_file(FIXTURE))
    config = test_config["detections"]["cloudtrail_sensitive"]
    det = CloudTrailSensitive(config)
    findings = _run_streaming(det, events)

    key_findings = [f for f in findings if "CreateAccessKey" in f.description]
    assert len(key_findings) == 1
    assert key_findings[0].attack_id == "T1098"


def test_detects_iam_policy_changes(test_config):
    """Positive: PutUserPolicy and AttachUserPolicy are sensitive."""
    events = list(cloudtrail.parse_file(FIXTURE))
    config = test_config["detections"]["cloudtrail_sensitive"]
    det = CloudTrailSensitive(config)
    findings = _run_streaming(det, events)

    policy_findings = [f for f in findings if "Policy" in f.description and "IAM" in f.description]
    assert len(policy_findings) == 2  # PutUserPolicy + AttachUserPolicy


def test_detects_public_s3_bucket(test_config):
    """Positive: PutBucketPolicy with Principal=* is critical."""
    events = list(cloudtrail.parse_file(FIXTURE))
    config = test_config["detections"]["cloudtrail_sensitive"]
    det = CloudTrailSensitive(config)
    findings = _run_streaming(det, events)

    s3_findings = [f for f in findings if "S3" in f.description]
    assert len(s3_findings) == 1
    assert s3_findings[0].severity == "critical"


def test_ignores_benign_actions(test_config):
    """Negative: DescribeInstances is not flagged."""
    events = list(cloudtrail.parse_file(FIXTURE))
    config = test_config["detections"]["cloudtrail_sensitive"]
    det = CloudTrailSensitive(config)
    findings = _run_streaming(det, events)

    describe_findings = [f for f in findings if "DescribeInstances" in f.description]
    assert len(describe_findings) == 0


def test_total_findings_from_fixture(test_config):
    """The fixture should produce exactly 5 findings from the sensitive detection."""
    events = list(cloudtrail.parse_file(FIXTURE))
    config = test_config["detections"]["cloudtrail_sensitive"]
    det = CloudTrailSensitive(config)
    findings = _run_streaming(det, events)

    # 1 ConsoleLogin without MFA + 1 CreateAccessKey + 2 IAM policy + 1 S3 public = 5
    assert len(findings) == 5


def test_ignores_non_cloudtrail_events(test_config):
    """Non-cloudtrail events are skipped entirely."""
    syslog_event = Event(
        timestamp=datetime(2026, 3, 15, 8, 0, 0, tzinfo=timezone.utc),
        source="syslog",
        event_type="auth",
        source_ip="10.0.0.1",
        username="root",
        raw="Mar 15 08:00:00 server sshd[1000]: Accepted password for root",
        fields={"process": "sshd", "message": "Accepted password"},
    )
    config = test_config["detections"]["cloudtrail_sensitive"]
    det = CloudTrailSensitive(config)
    findings = _run_streaming(det, [syslog_event])
    assert len(findings) == 0
