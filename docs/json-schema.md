# LogHound JSON Output Schema (v2.0)

## Overview

LogHound exports findings as **JSON Lines** (`.jsonl`): one JSON object per line, no wrapping array. This format is easy to process with `jq`, `grep`, Python, or any streaming JSON parser.

```bash
loghound auth.log --json --output findings.jsonl
```

## Schema

Each line is a JSON object with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `detection_name` | `string` | Rule that triggered (e.g., `ssh_brute_force`) |
| `severity` | `string` | One of: `critical`, `high`, `medium`, `low` |
| `attack_id` | `string \| null` | MITRE ATT&CK technique ID (e.g., `T1110`) |
| `timestamp` | `string` | ISO 8601 UTC timestamp of the finding |
| `entities` | `object` | Key-value map of affected entities |
| `description` | `string` | Human-readable summary of the finding |
| `evidence` | `string[]` | Raw log lines supporting the finding |
| `false_positive_notes` | `string` | Guidance for triaging false positives |
| `count` | `integer` | Number of deduplicated occurrences (1 = unique) |
| `suppressed` | `boolean` | `true` if finding was allowlisted |
| `suppression_reason` | `string \| null` | Why the finding was suppressed |
| `ioc_hits` | `string[]` | IPs matched against the IOC list |
| `entity_risk` | `object` | Per-entity risk scores (`"source_ip:1.2.3.4": 15`) |

## Entity Keys

The `entities` object uses these keys:

| Key | Description |
|-----|-------------|
| `source_ip` | Origin IP address |
| `username` | Affected user account |

## Entity Risk Keys

The `entity_risk` object uses composite keys: `"<entity_type>:<entity_value>"`, e.g.:

```json
{
  "source_ip:203.0.113.42": 15,
  "username:jdoe": 3
}
```

Risk scores aggregate severity weights across all findings for that entity.

## Detection Names

| Detection | Severity | ATT&CK | Description |
|-----------|----------|--------|-------------|
| `ssh_brute_force` | high | T1110 | Failed SSH logins exceeding threshold |
| `successful_after_brute` | critical | T1110 | Successful login after brute force |
| `off_hours_login` | medium | T1078 | Login outside business hours |
| `web_recon` | medium | — | Excessive 4xx responses from one IP |
| `suspicious_user_agent` | medium | — | Known scanner user agents |
| `privilege_escalation` | medium | T1548 | sudo failures/first-time sudo usage |
| `password_spraying` | high | T1110.003 | One IP, many usernames |
| `new_ip_for_user` | low | T1078 | Login from previously unseen IP |
| `cloudtrail_sensitive_actions` | high/critical | T1078.004/T1098 | Sensitive AWS API calls |

## Example

```json
{
  "detection_name": "ssh_brute_force",
  "severity": "high",
  "attack_id": "T1110",
  "timestamp": "2026-03-15T14:31:02+00:00",
  "entities": {"source_ip": "203.0.113.42"},
  "description": "SSH brute force from 203.0.113.42: 5 failed login attempts in 10 minutes",
  "evidence": [
    "Mar 15 14:31:02 ubuntu-server sshd[19102]: Failed password for root from 203.0.113.42 port 44521 ssh2"
  ],
  "false_positive_notes": "Could be a legitimate user repeatedly typing their password wrong.",
  "count": 1,
  "suppressed": false,
  "suppression_reason": null,
  "ioc_hits": [],
  "entity_risk": {"source_ip:203.0.113.42": 15}
}
```

## Usage with jq

```bash
# All critical findings
cat findings.jsonl | jq 'select(.severity == "critical")'

# Non-suppressed findings only
cat findings.jsonl | jq 'select(.suppressed == false)'

# Unique detection names
cat findings.jsonl | jq -r '.detection_name' | sort -u

# Top entities by risk
cat findings.jsonl | jq '.entity_risk' | jq -s 'add | to_entries | sort_by(-.value)'

# IOC hits only
cat findings.jsonl | jq 'select(.ioc_hits | length > 0)'

# Findings for a specific IP
cat findings.jsonl | jq 'select(.entities.source_ip == "203.0.113.42")'
```

## Stability

This schema is stable for v2.0. Fields will not be removed or renamed within a major version. New fields may be added.
