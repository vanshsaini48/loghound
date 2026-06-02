"""CloudTrail JSON parser (Phase 2).

AWS CloudTrail log files are a single JSON object with a "Records" array.
Each record maps to one Event via:
  sourceIPAddress  -> source_ip
  userIdentity.arn -> username  (falls back to userName, principalId)
  eventName        -> event_type
  eventTime        -> timestamp (ISO 8601, always UTC)
  everything else  -> fields dict
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser

from ..events import Event
from .reader import smart_open


def can_parse(sample_lines: list[str]) -> bool:
    """Detect CloudTrail by looking for the {"Records": [...]} wrapper."""
    if not sample_lines:
        return False
    joined = "\n".join(sample_lines)
    try:
        data = json.loads(joined)
    except (json.JSONDecodeError, ValueError):
        # Might be truncated — look for signature keys in raw text
        return '"Records"' in joined and '"eventVersion"' in joined
    return isinstance(data, dict) and "Records" in data


def _extract_username(identity: dict) -> str | None:
    """Pull the most useful identity string from userIdentity."""
    if not identity:
        return None
    # Prefer ARN, fall back to userName, then principalId
    arn = identity.get("arn")
    if arn:
        # Extract the trailing resource part: arn:aws:iam::123:user/alice -> user/alice
        parts = arn.split(":")
        return parts[-1] if parts else arn
    return identity.get("userName") or identity.get("principalId")


def _parse_timestamp(raw: str) -> datetime | None:
    try:
        dt = dateutil_parser.parse(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except (ValueError, OverflowError, TypeError):
        return None


def parse_file(file_path: Path, show_progress: bool = False):
    """Parse a CloudTrail JSON file, yielding Event objects lazily."""
    skipped = 0
    with smart_open(file_path, show_progress=show_progress) as f:
        raw_text = f.read()

    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        print(f"[cloudtrail parser] failed to parse JSON in {file_path}")
        return

    records = data.get("Records", [])
    if not isinstance(records, list):
        print(f"[cloudtrail parser] 'Records' is not a list in {file_path}")
        return

    for record in records:
        if not isinstance(record, dict):
            skipped += 1
            continue

        ts = _parse_timestamp(record.get("eventTime", ""))
        if ts is None:
            skipped += 1
            continue

        identity = record.get("userIdentity", {})
        username = _extract_username(identity)
        source_ip = record.get("sourceIPAddress")
        event_name = record.get("eventName", "unknown")

        # Build fields with all CloudTrail-specific data
        fields = {
            "event_name": event_name,
            "event_source": record.get("eventSource", ""),
            "aws_region": record.get("awsRegion", ""),
            "user_agent": record.get("userAgent", ""),
            "error_code": record.get("errorCode", ""),
            "error_message": record.get("errorMessage", ""),
        }

        # Flatten userIdentity into fields
        if identity:
            fields["user_identity_type"] = identity.get("type", "")
            fields["user_identity_arn"] = identity.get("arn", "")
            if "sessionContext" in identity:
                sc = identity["sessionContext"]
                mfa = sc.get("attributes", {}).get("mfaAuthenticated")
                if mfa is not None:
                    fields["mfa_authenticated"] = str(mfa).lower()

        # Request/response parameters (useful for detection context)
        req = record.get("requestParameters")
        if req and isinstance(req, dict):
            fields["request_parameters"] = json.dumps(req)
        resp = record.get("responseElements")
        if resp and isinstance(resp, dict):
            fields["response_elements"] = json.dumps(resp)

        yield Event(
            timestamp=ts,
            source="cloudtrail",
            event_type=event_name,
            source_ip=source_ip,
            username=username,
            raw=json.dumps(record),
            fields=fields,
        )

    if skipped:
        print(f"[cloudtrail parser] skipped {skipped} unparseable records")
