"""AWS CloudTrail JSON parser."""

import json
from pathlib import Path
from datetime import datetime
from ..events import Event
from .reader import smart_open


def can_parse(sample_lines: list[str]) -> bool:
    """CloudTrail logs: JSON with 'Records' key or individual events."""
    if not sample_lines:
        return False
    
    # Try to parse as individual JSON lines
    for line in sample_lines[:10]:
        line = line.strip()
        if not line or line.startswith("{"):
            try:
                obj = json.loads(line)
                if "Records" in obj or ("eventID" in obj and "eventSource" in obj):
                    return True
            except json.JSONDecodeError:
                pass
    
    # Try to parse multi-line
    joined = "\n".join(sample_lines[:50])
    if '"Records"' in joined or ('"eventID"' in joined and '"eventSource"' in joined):
        return True
    
    return False


def parse_file(file_path: Path, show_progress: bool = False):
    """Parse a CloudTrail JSON file and yield events."""
    with smart_open(file_path, show_progress=show_progress) as f:
        content = f.read()
    
    # Try to parse as single JSON object (bulk export)
    try:
        obj = json.loads(content)
        records = obj.get("Records", [])
        if records:
            for record in records:
                event = _parse_record(record)
                if event:
                    yield event
            return
    except json.JSONDecodeError:
        pass
    
    # Fall back to line-by-line parsing
    with smart_open(file_path, show_progress=show_progress) as f:
        for event in parse(f):
            yield event


def parse(lines):
    """Parse CloudTrail JSON events (line-by-line)."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        
        records = obj.get("Records", [])
        if not records:
            records = [obj]
        
        for record in records:
            try:
                event = _parse_record(record)
                if event:
                    yield event
            except Exception:
                pass


def _extract_username_from_arn(arn: str) -> str | None:
    """Extract username from ARN like arn:aws:iam::123456789012:user/alice."""
    if not arn or ":user/" not in arn and ":role/" not in arn:
        return None
    
    # Split by : and take the last part (user/alice)
    parts = arn.split(":")
    if len(parts) >= 6:
        resource = parts[-1]  # "user/alice" or "role/something"
        if "/" in resource:
            return resource  # "user/alice"
    
    return None


def _parse_record(record: dict) -> Event | None:
    """Convert a CloudTrail record to an Event."""
    
    event_time_str = record.get("eventTime")
    if not event_time_str:
        return None
    
    try:
        timestamp = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
    except ValueError:
        return None
    
    source_ip = record.get("sourceIPAddress")
    user_identity = record.get("userIdentity", {})
    
    # Extract username: prefer ARN, then userName, then principalId
    username = None
    arn = user_identity.get("arn")
    if arn:
        username = _extract_username_from_arn(arn)
    if not username:
        username = user_identity.get("userName") or user_identity.get("principalId")
    
    event_name = record.get("eventName", "")
    event_source = record.get("eventSource", "cloudtrail")
    raw = json.dumps(record, default=str)
    
    mfa_auth = user_identity.get("sessionContext", {}).get("attributes", {}).get("mfaAuthenticated", "")
    
    fields = {
        "event_name": event_name,
        "event_source": event_source,
        "aws_region": record.get("awsRegion", ""),
        "user_agent": record.get("userAgent", ""),
        "error_code": record.get("errorCode", ""),
        "error_message": record.get("errorMessage", ""),
        "mfa_authenticated": mfa_auth,
    }
    
    return Event(
        timestamp=timestamp,
        source="cloudtrail",
        event_type=event_name,
        source_ip=source_ip,
        username=username,
        raw=raw,
        fields=fields,
    )
