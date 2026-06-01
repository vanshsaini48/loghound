# Software Requirements Specification
## loghound — A Terminal Tool for Security Log Triage

- **Version:** 1.0  
- **Author:** [Your Name]  
- **Last Updated:** [Date]  
- **Status:** Draft  

---

# 1. Introduction

## 1.1 Purpose

This document specifies the requirements for `loghound`, a terminal-based log analysis tool that helps junior security analysts identify suspicious activity in common server logs.

It defines the scope, functional and non-functional requirements, system constraints, and acceptance criteria.

## 1.2 Scope

`loghound` is a standalone command-line and terminal-UI application written in Python.

It ingests log files:

- Linux auth logs
- Apache/Nginx access logs
- Generic JSON logs

The tool applies a fixed set of detection rules informed by common attacker techniques and presents findings in an interactive interface.

It can export findings as a Markdown incident report.

The tool is intended for offline triage of bounded log files (under approximately 1 GB), not as a real-time SIEM or production monitoring system.

### Out of Scope

- Real-time log streaming
- Multi-host correlation
- Machine learning detection
- Alert delivery (email/Slack)
- Authentication/multi-user features

## 1.3 Intended Audience

The primary audience for this document is:

- The developer (single contributor)
- Future reviewers (interviewer, recruiter, collaborator)

## 1.4 Definitions and Acronyms

| Term | Meaning |
|---|---|
| TUI | Terminal User Interface |
| CLI | Command-Line Interface |
| IOC | Indicator of Compromise |
| ATT&CK | MITRE Adversarial Tactics, Techniques, and Common Knowledge framework |
| FP | False Positive |
| Detection | A coded rule that identifies a suspicious pattern in logs |
| Finding | An instance where a detection matched input data |

## 1.5 References

- MITRE ATT&CK Framework: https://attack.mitre.org
- Sigma Detection Rule format (inspirational, not enforced): https://github.com/SigmaHQ/sigma
- Common Event Format (CEF)
- JSON log conventions

---

# 2. Overall Description

## 2.1 Product Perspective

`loghound` is a self-contained Python application with:

- No server component
- No database backend
- No external network dependencies for core functionality

It reads files from disk and writes reports to disk.

### Architecture Overview

```text
Parser Layer -> Event Stream -> Detection Engine -> Findings -> CLI/TUI Renderer
```

## 2.2 Product Functions

At a high level, `loghound` performs the following:

1. Auto-detect the format of an input log file
2. Parse the file into a normalized event stream
3. Apply a library of detection rules against the event stream
4. Present findings in an interactive TUI with filtering and pivoting
5. Export an analyst-readable Markdown incident report

## 2.3 User Characteristics

The expected user is:

- A junior SOC analyst
- A cybersecurity student
- A CTF participant

Users are assumed to understand:

- SSH
- HTTP
- Brute force attacks
- Basic security concepts

## 2.4 Operating Environment

| Component | Requirement |
|---|---|
| Operating System | Linux (primary), macOS (best-effort) |
| Python Version | 3.10+ |
| Terminal | Modern terminal emulator with 256-color support |
| Storage | No persistent storage beyond logs and reports |

## 2.5 Design and Implementation Constraints

- Single developer
- 4-week build window
- Beginner-level Python proficiency at project start
- Dependencies must be pure Python or use prebuilt wheels
- No paid APIs/services
- Tool must run fully offline
- Input logs assumed well-formed
- Log timestamps assumed parseable
- Ambiguous-year logs assume current year
- Users must have read access to log files

---

# 3. Functional Requirements

Each requirement includes a unique ID for traceability.

---

# 3.1 Log Ingestion (FR-1.x)

### FR-1.1
The system shall accept a file path as a positional command-line argument.

### FR-1.2
The system shall auto-detect log format from the first 50 lines.

Supported formats:

- Linux auth log (syslog)
- Apache/Nginx Common Log Format
- JSON-lines logs

### FR-1.3
The system shall allow users to override auto-detection using:

```bash
--format
```

### FR-1.4
Unsupported formats shall:

- Produce a clear error message
- Return a non-zero exit code

### FR-1.5
The system shall handle files up to 1 GB without exceeding 500 MB resident memory.

---

# 3.2 Event Parsing (FR-2.x)

### FR-2.1
Each log line shall be parsed into a normalized event object containing:

- Timestamp
- Source IP
- Username
- Event type
- Raw message
- Free-form fields dictionary

### FR-2.2
Lines that fail parsing shall:

- Be counted
- Be reported
- Not crash the tool

### FR-2.3
Timestamps shall be normalized to UTC internally.

---

# 3.3 Detection Engine (FR-3.x)

## FR-3.1 SSH Brute Force

Detect:

- Five or more failed SSH logins
- Same source IP
- Within a 10-minute window

Thresholds shall be configurable.

## FR-3.2 Successful Login After Brute Force

Detect successful authentication from an IP that exceeded brute-force thresholds within the previous 60 minutes.

**ATT&CK Mapping:** T1110

## FR-3.3 Off-Hours Authentication

Detect successful interactive logins outside configurable business hours.

**ATT&CK Mapping:** T1078

## FR-3.4 Web Reconnaissance

Detect:

- More than 50 requests
- From a single IP
- Resulting in 4xx responses
- Within 5 minutes

Indicates scanning/enumeration behavior.

## FR-3.5 Suspicious UserAgent

Detect scanner-related user agents including:

- sqlmap
- nikto
- nmap
- masscan
- gobuster
- ffuf
- curl/wget without referrer patterns

## FR-3.6 Privilege Escalation Indicators

Detect:

- sudo failures followed by success within 5 minutes
- First-time sudo usage by an account

### Each detection shall produce findings containing:

- Detection name
- Severity
- Timestamp
- Affected entities
- Supporting evidence
- ATT&CK technique ID
- False-positive notes

---

# 3.4 User Interface (FR-4.x)

## FR-4.1
The system shall provide:

```bash
--report
```

mode for plain-text reporting.

## FR-4.2
The system shall provide an interactive TUI with:

### Left Panel

- Findings list
- Sort by severity/timestamp

### Right Panel

- Finding details

### Keybindings

| Key | Action |
|---|---|
| Arrow Keys | Navigation |
| 1 / 2 / 3 | Filter by severity |
| p | Pivot on entity |
| e | Export report |

## FR-4.3
Pivoting on IP/username shall show:

- Related findings
- Raw events

## FR-4.4
The TUI shall display:

- Detection counts
- Total processed events

---

# 3.5 Reporting (FR-5.x)

## FR-5.1
The system shall export findings as a Markdown report containing:

- Executive summary
- Counts by severity
- Findings table
- Detailed sections per finding
- Evidence lines

## FR-5.2
Reports shall include an empty:

```text
Analyst Notes
```

section for manual annotations.

## FR-5.3
Default output path:

```text
./loghound-report-<timestamp>.md
```

Overridable with:

```bash
--output
```

---

# 3.6 Configuration (FR-6.x)

## FR-6.1
Detection thresholds shall be configurable through YAML config files.

Example:

```bash
--config
```

## FR-6.2
A default config shall ship with the tool.

---

# 4. Non-Functional Requirements

# 4.1 Performance

## NFR-1.1
The system shall process a 100 MB auth log in under 30 seconds.

## NFR-1.2
TUI interactions shall not block longer than 200 ms.

---

# 4.2 Usability

## NFR-2.1
The tool shall run end-to-end in 3 commands or fewer.

## NFR-2.2
Errors shall include:

- File name
- Line number
- Suggested fix

## NFR-2.3
The TUI shall include a help overlay accessible via:

```text
?
```

---

# 4.3 Reliability

## NFR-3.1
Malformed lines shall not crash the tool.

## NFR-3.2
Documented exit codes:

| Code | Meaning |
|---|---|
| 0 | Success, no findings |
| 1 | Success, findings present |
| 2 | Input error |
| 3 | Internal error |

---

# 4.4 Maintainability

## NFR-4.1
Detection rules shall exist as separate modules under:

```text
src/detections/
```

Each exports:

```python
run(events, config) -> list[Finding]
```

## NFR-4.2
Adding a new detection shall require modifying no more than:

- The new detection module
- A registration list

## NFR-4.3
Code formatting/linting:

- black
- ruff

---

# 4.5 Portability

## NFR-5.1
The tool shall install using:

```bash
pip install .
```

No system-level dependencies beyond Python 3.10+.

---

# 4.6 Testability

## NFR-6.1
Each detection shall include:

- One positive test case
- One negative test case

## NFR-6.2
Sample logs shall exist under:

```text
tests/fixtures/
```

---

# 5. System Architecture (High-Level)

```text
[Input File]
      ↓
[Parser]
      ↓
[Normalized Events]
      ↓
[Detection Engine]
      ↓
[Findings]
      ↓
[Renderer: CLI or TUI]
      ↓
[Markdown Report]
```

Each stage has:

- A single responsibility
- A defined interface
- Easy extensibility
- Independent testability

A detailed architecture diagram will live in:

```text
docs/ARCHITECTURE.md
```

---

# 6. Acceptance Criteria

Version 1.0 is complete when:

1. The tool installs cleanly on a fresh Linux VM
2. All six baseline detections are implemented
3. The TUI keybindings work
4. Markdown report export functions correctly
5. README includes:
   - Quick start
   - Demo GIF
   - Architecture overview
   - LIMITATIONS.md link
6. The `tests/` directory contains at least 12 passing tests
7. Repository has a tagged `v1.0.0` release

---

# 7. Out of Scope (Explicit Non-Goals)

- Real-time log tailing
- Multi-file correlation
- Multi-host correlation
- Authentication/RBAC
- Web UI
- SIEM integrations
- Ticketing/chat integrations
- Machine learning detection
- Windows EVTX parsing (possible v2.0)
- Encrypted/compressed logs

---

# 8. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| TUI learning curve consumes too much time | Medium | High | Build CLI first |
| Time parsing edge cases | High | Medium | Use `dateutil` |
| Too many false positives | Medium | Medium | Tune thresholds early |
| Large files consume memory | Low | High | Stream parse line-by-line |

---

# 9. Glossary of Detection Rules (Reference)

Each detection will eventually receive its own Markdown writeup under:

```text
docs/detections/
```

Each writeup should include:

- Technique description
- ATT&CK mapping
- Log signatures
- False-positive scenarios
- Tuning guidance

---

# 10. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 0.1 | [Date] | [You] | Initial draft |
| 1.0 | [Date] | [You] | Locked for implementation start |

