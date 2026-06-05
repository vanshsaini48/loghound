cat > README.md << 'EOF'
# loghound

A terminal tool for security log triage. Feed it a log file, get back a prioritized list of suspicious activity mapped to MITRE ATT&CK techniques.

Built for junior SOC analysts, cybersecurity students, and CTF participants who need to triage auth logs and web access logs without spinning up a SIEM.

<!-- TODO: demo GIF here -->

---

## Quick Start

```bash
pip install .
loghound /var/log/auth.log
```

That's it. loghound auto-detects the log format, runs nine detection rules, scores entities by risk, and prints a severity-sorted summary.

### Generate a Markdown incident report

```bash
loghound /var/log/auth.log --report
```

Writes a timestamped report with executive summary, ATT&CK technique summary, investigation timeline, findings table, evidence lines, and a blank analyst-notes section.

### Export machine-readable JSON

```bash
loghound /var/log/auth.log --json -o findings.jsonl
```

One JSON object per line — pipe to `jq`, feed into a SIEM, or process with Python. Schema documented in [docs/json-schema.md](docs/json-schema.md).

### Interactive Dashboard

```bash
loghound /var/log/auth.log --tui
```

Dashboard with summary panel, sparkline, risk-sorted findings list, and detail pane. Search, sort, pivot, and export without leaving the terminal.

---

## What It Detects

| Detection | Severity | ATT&CK | What it finds |
|-----------|----------|--------|---------------|
| SSH Brute Force | HIGH | T1110 | 5+ failed SSH logins from one IP in 10 minutes |
| Successful Login After Brute Force | CRITICAL | T1110 | Auth success from a brute-forcing IP |
| Off-Hours Authentication | MEDIUM | T1078 | Interactive logins outside business hours |
| Web Reconnaissance | MEDIUM | — | 50+ requests yielding 4xx from one IP in 5 minutes |
| Suspicious User Agent | MEDIUM | — | Scanner signatures: sqlmap, nikto, gobuster, ffuf, etc. |
| Privilege Escalation Indicators | MEDIUM | T1548 | sudo failures followed by success, or first-time sudo |
| Password Spraying | HIGH | T1110.003 | One IP attempting many distinct usernames |
| New Source IP for User | LOW | T1078 | Login from an IP never seen before for that user |
| CloudTrail Sensitive Actions | HIGH/CRITICAL | T1078.004/T1098 | CreateAccessKey, ConsoleLogin without MFA, S3 bucket policy changes, IAM policy changes |

All thresholds and time windows are configurable via YAML.

---

## Triage Features (v2.0)

| Feature | What it does |
|---------|-------------|
| **Allowlist suppression** | Config-driven IP/user allowlists suppress noisy findings |
| **Entity risk scoring** | Per-entity (IP, user) risk aggregated across all findings |
| **Finding deduplication** | Repeated identical findings collapse into one with a count |
| **IOC matching** | Match source IPs against local threat intelligence list |
| **Time filtering** | `--since` and `--until` restrict analysis to a time window |
| **Multi-file merge** | Analyze rotated logs (`auth.log*`) in time order |

---

## Supported Log Formats

| Format | Source | Auto-detected |
|--------|--------|---------------|
| Linux auth log (syslog) | `/var/log/auth.log`, `/var/log/secure` | ✅ |
| Apache access log | Common/Combined Log Format | ✅ |
| Nginx access log | Common/Combined Log Format | ✅ |
| JSON-lines | Generic structured logs | ✅ |
| AWS CloudTrail | Bulk export or streaming JSON | ✅ |

loghound auto-detects the format from the first 50 lines. Override with `--format`.

Gzipped (`.gz`) files are read transparently.

---

## TUI Keybindings

| Key | Action |
|-----|--------|
| ↑ / ↓ | Navigate findings |
| `/` | Live search / filter |
| `Escape` | Clear search |
| `1` | Filter: CRITICAL only |
| `2` | Filter: HIGH only |
| `3` | Filter: MEDIUM only |
| `0` | Show all findings |
| `s` | Cycle sort: risk → time → severity |
| `p` | Pivot on selected entity |
| `e` | Export Markdown report |
| `?` | Help overlay |
| `q` | Quit |

---

## Configuration

```bash
loghound auth.log --config my_config.yaml
```

Example config:

```yaml
business_hours:
  start: "08:00"
  end: "19:00"
  timezone: "UTC"

allowlist:
  ips: ["10.0.0.5"]
  users: ["backup-svc"]

ioc:
  list_path: "default"  # or path to custom IOC file

scoring:
  severity_weights: { critical: 10, high: 4, medium: 2, low: 1 }

detections:
  ssh_brute_force: { enabled: true, threshold: 5, window_minutes: 10 }
  password_spraying: { enabled: true, distinct_users: 10, window_minutes: 15 }
  off_hours_login: { enabled: true }
  cloudtrail_sensitive: { enabled: true }
```

Override IOC list for a single run:

```bash
loghound auth.log --ioc-file indicators.txt
```

---

## CLI Reference

```bash
loghound <log_files...> [options]

Options:
  --format FORMAT     Override auto-detection (syslog, apache, nginx, json, cloudtrail)
  --config PATH       Config file (default: bundled config)
  --since TIMESTAMP   Only process events at or after this time (ISO 8601)
  --until TIMESTAMP   Only process events before this time (ISO 8601)
  --report            Export Markdown report
  --json              Export JSON-lines
  --tui               Launch interactive dashboard
  --output PATH       Output file path
  --ioc-file PATH     Override IOC list for this run
```

---

## Architecture

Full architecture documentation: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings |
| 1 | Success, findings present |
| 2 | Input error |
| 3 | Internal error |

---

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

92 tests passing, covering parsers, detections, triage, and integration.

---

## Requirements

- Python 3.10+
- Linux (primary) or macOS (best-effort)
- Terminal with 256-color support (for TUI)

No database, no network access, no paid APIs. Fully offline.

---

## Limitations

- **Offline only** — no real-time log tailing or alerting
- **Single host** — merges rotated logs from the same host, not cross-host correlation
- **No ML** — rule-based detections only
- **No EVTX** — Windows Event Log parsing is planned for v2.1

See [LIMITATIONS.md](LIMITATIONS.md) for full list.

---

## License

MIT
EOF