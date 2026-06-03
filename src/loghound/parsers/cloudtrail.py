"""AWS CloudTrail JSON parser."""

import json
from pathlib import Path
from datetime import datetime
from ..events import Event
from .reader import smart_open


def can_parse(sample_lines: list[str]) -> bool:
    """CloudTrail logs are JSON with 'Records' key or eventID."""
    for line in sample_lines[:10]:
        try:
            obj = json.loads(line)
            if "Records" in obj or ("eventID" in obj and "eventSource" in obj):
                return True
        except (json.JSONDecodeError, TypeError):
            pass
    return False


def parse_file(file_path: Path, show_progress: bool = False):
    """Parse a CloudTrail JSON file and yield events."""
    with smart_open(file_path, show_progress=show_progress) as f:
        for event in parse(f):
            yield event


def parse(lines):
    """Parse CloudTrail JSON events.
    
    Each line is either:
    - A JSON object with 'Records' array (bulk export)
    - A single CloudTrail record (streaming format)
    """
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        
        # Handle Records array
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


def _parse_record(record: dict) -> Event | None:
    """Convert a CloudTrail record to an Event."""
    
    # Extract timestamp
    event_time_str = record.get("eventTime")
    if not event_time_str:
        return None
    
    try:
        # CloudTrail uses ISO format: 2026-03-15T14:31:23Z
        timestamp = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
    except ValueError:
        return None
    
    # Extract IPs and user
    source_ip = record.get("sourceIPAddress")
    username = record.get("userIdentity", {}).get("principalId")
    
    event_name = record.get("eventName", "")
    event_source = record.get("eventSource", "cloudtrail")
    
    # Build evidence string
    raw = json.dumps(record, default=str)
    
    # Store source-specific data in fields
    fields = {
        "eventName": event_name,
        "eventSource": event_source,
        "awsRegion": record.get("awsRegion", ""),
        "userAgent": record.get("userAgent", ""),
        "errorCode": record.get("errorCode", ""),
        "errorMessage": record.get("errorMessage", ""),
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
