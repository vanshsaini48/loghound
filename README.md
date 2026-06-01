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

That's it. loghound auto-detects the log format, runs six detection rules, and prints a severity-sorted summary.

### Generate a Markdown incident report

```bash
loghound /var/log/auth.log --report
```

Writes a timestamped report to `./loghound-report-<timestamp>.md` with an executive summary, findings table, evidence lines, and a blank analyst-notes section.

### Interactive TUI

```bash
loghound /var/log/auth.log --tui
```

Two-panel interface: findings list on the left, detail view on the right. Filter by severity, pivot on IPs and usernames, export a report — all without leaving the terminal.

---

## What It Detects

| Detection | Severity | ATT&CK | What it finds |
|-----------|----------|--------|---------------|
| SSH Brute Force | HIGH | — | 5+ failed SSH logins from one IP in 10 minutes |
| Successful Login After Brute Force | CRITICAL | T1110 | Authentication success from a brute-forcing IP |
| Off-Hours Authentication | MEDIUM | T1078 | Interactive logins outside business hours |
| Web Reconnaissance | HIGH | — | 50+ requests yielding 4xx responses from one IP in 5 minutes |
| Suspicious User Agent | MEDIUM | — | Scanner signatures: sqlmap, nikto, gobuster, ffuf, and others |
| Privilege Escalation Indicators | HIGH | — | sudo failures followed by success, or first-time sudo usage |

All thresholds and time windows are configurable via YAML.

---

## TUI Keybindings

| Key | Action |
|-----|--------|
| Up / Down | Navigate findings |
| 1 | Filter: CRITICAL only |
| 2 | Filter: HIGH only |
| 3 | Filter: MEDIUM only |
| 0 | Show all findings |
| p | Pivot on selected finding's IP or username |
| e | Export Markdown report |
| q | Quit |

---

## Supported Log Formats

- **Linux auth logs** (syslog) — `/var/log/auth.log`, `/var/log/secure`
- **Apache / Nginx access logs** (Common Log Format)

loghound auto-detects the format from the first 50 lines. No flags needed.

---

## Configuration

Ship a custom config to tune thresholds:

```bash
loghound auth.log --config my_config.yaml
```

Example config:

```yaml
business_hours:
  start: "08:00"
  end: "19:00"
  timezone: "UTC"

detections:
  ssh_brute_force:
    enabled: true
    threshold: 5
    window_minutes: 10

  off_hours_login:
    enabled: true
```

A default config ships with the package. Override only what you need.

---

## Architecture

```
Input File -> Parser -> Normalized Events -> Detection Engine -> Findings -> Renderer
```

The system is a four-stage pipeline. Each stage has a single responsibility and a defined interface:

- **Parsers** stream events line-by-line. Memory stays flat regardless of file size.
- **Events** are immutable dataclasses with a common schema. The raw line is always preserved.
- **Detections** are independent modules. Each receives the full event list and a config dict, and returns findings. Adding a detection means writing one module and registering it.
- **Renderers** consume a list of findings. The CLI summary, TUI, and Markdown reporter are all independent.

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

## Requirements

- Python 3.10+
- Linux (primary) or macOS (best-effort)
- Terminal with 256-color support (for TUI)

No database, no network access, no paid APIs. Fully offline.

---

## Limitations

See [LIMITATIONS.md](LIMITATIONS.md) for explicit non-goals and known constraints.

---

## License

MIT
