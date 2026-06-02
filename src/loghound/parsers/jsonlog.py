import json
from pathlib import Path
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser
from ..events import Event
from .reader import smart_open

TIMESTAMP_KEYS = ['timestamp', 'time', '@timestamp', 'ts', 'datetime']
IP_KEYS = ['source_ip', 'src_ip', 'remote_addr', 'client_ip', 'ip']
USER_KEYS = ['username', 'user', 'actor', 'user_name']
TYPE_KEYS = ['level', 'severity', 'event_type', 'type', 'log_level']
MESSAGE_KEYS = ['message', 'msg', 'text']


def can_parse(sample_lines: list[str]) -> bool:
    if not sample_lines:
        return False
    json_count = 0
    checked = 0
    for line in sample_lines[:20]:
        line = line.strip()
        if not line:
            continue
        checked += 1
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                json_count += 1
        except (json.JSONDecodeError, ValueError):
            pass
    return checked > 0 and json_count >= max(1, checked // 2)


def _first_match(data: dict, keys: list[str]):
    for k in keys:
        if k in data:
            return data[k]
    return None


def _parse_timestamp(raw_ts) -> datetime | None:
    if raw_ts is None:
        return None
    if isinstance(raw_ts, (int, float)):
        return datetime.fromtimestamp(raw_ts, tz=timezone.utc)
    try:
        dt = dateutil_parser.parse(str(raw_ts))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except (ValueError, OverflowError):
        return None


def parse_file(file_path: Path):
    skipped = 0
    with smart_open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                skipped += 1
                continue

            if not isinstance(data, dict):
                skipped += 1
                continue

            ts = _parse_timestamp(_first_match(data, TIMESTAMP_KEYS))
            if ts is None:
                skipped += 1
                continue

            event_type = _first_match(data, TYPE_KEYS) or 'jsonlog'
            source_ip = _first_match(data, IP_KEYS)
            username = _first_match(data, USER_KEYS)
            message = _first_match(data, MESSAGE_KEYS) or ''

            used_keys = set(TIMESTAMP_KEYS + IP_KEYS + USER_KEYS + TYPE_KEYS + MESSAGE_KEYS)
            fields = {k: v for k, v in data.items() if k not in used_keys}
            fields['message'] = message

            yield Event(
                timestamp=ts,
                source=str(file_path),
                event_type=str(event_type),
                source_ip=str(source_ip) if source_ip else None,
                username=str(username) if username else None,
                raw=line,
                fields=fields,
            )

    if skipped:
        print(f'[jsonlog parser] skipped {skipped} unparseable lines')
