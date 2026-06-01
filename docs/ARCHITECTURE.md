# Architecture — loghound

**Status:** Living document. Updated as design decisions evolve.  
**Audience:** The developer (you), future contributors, and reviewers (recruiters, interviewers).  
**Related:** `SRS.md` for the formal requirements this architecture implements.

---

# 1. Purpose of This Document

The SRS describes what `loghound` does. This document describes how it's built, why it's structured that way, and what the boundaries between components are.

If you ever need to rewrite a piece of `loghound`, this document tells you exactly which interfaces you must preserve.

A reader should be able to finish this document and confidently answer:

- What are the major components?
- What data flows between them?
- Why is the system split this way and not another way?
- Where would I add a new feature like "Windows EVTX parsing" or "a new detection"?

---

# 2. Guiding Principles

Every design decision in `loghound` follows these principles.

## P1. One thing at a time, well

Each module has one responsibility.

A parser parses; it does not detect.  
A detection detects; it does not render.

This makes every piece independently testable and replaceable.

---

## P2. Data, not state

The system is a pipeline that transforms data.

There are no long-lived objects holding hidden state across stages.

An `Event` is a value; a `Finding` is a value.

Pipelines made of pure transformations are easier to reason about, test, and parallelize later.

---

## P3. Configuration, not code

Thresholds, time windows, and business-hours definitions live in YAML, not in `if` statements.

This separates security policy (what counts as suspicious) from engineering (how we look for it).

The same code should serve different organizations with different policies.

---

## P4. Streaming, not loading

Logs can be large.

The system reads them line-by-line and never holds the whole file in memory.

This is non-negotiable — it's the difference between a tool that works on real logs and one that only works on demos.

---

## P5. Fail loudly on bugs, gracefully on data

A malformed log line should be counted and skipped.

A bug in our parser should crash with a clear traceback.

Never silently swallow exceptions.

---

## P6. Test the contract, not the implementation

Tests should exercise public interfaces.

If a test breaks because you renamed an internal helper, the test was testing the wrong thing.

---

# 3. High-Level Architecture

`loghound` is a four-stage pipeline with two output renderers.

```text
+-------------+
| Input file  |
| (auth.log,  |
| access.log, |
| events.json)|
+------+------+
       |
       v
+-------------+   Stage 1: Ingestion
| Parser      | - format detection
| Layer       | - line-by-line read
+------+------+
       |
       | yields Event objects
       v
+-------------+   Stage 2: Normalization
| Normalized  | - timestamps in UTC
| Event       | - common fields populated
| Stream      | - raw line preserved
+------+------+
       |
       | consumed by detections
       v
+-------------+   Stage 3: Detection
| Detection   | - each detection is a module
| Engine      | - thresholds from config
+------+------+
       |
       | list[Finding]
       v
+---------------------+ Stage 4: Presentation
|                     |
v                     v
+-----------+   +----------+
| CLI/TUI   |   | Markdown |
| Renderer  |   | Reporter |
+-----------+   +----------+
```

The normalized event stream is the key architectural decision.

- New log formats plug in at the parser layer without touching detections.
- New detections plug in at the engine layer without touching parsers.
- New output formats plug in at the renderer layer without touching anything else.

---

# 4. Component Breakdown

## 4.1 CLI Layer (`src/loghound/cli.py`)

### Responsibility

- Parse command-line arguments
- Load configuration
- Wire up the pipeline
- Dispatch to renderers
- Return exit codes

### What lives here

- `argparse` setup
- Loading YAML config
- Choosing renderer
- Top-level exception handling

### What does NOT live here

- Parsing logic
- Detection logic
- Unit-testable business logic

---

## 4.2 Parser Layer (`src/loghound/parsers/`)

### Structure

```text
parsers/
├── base.py
├── syslog.py
├── apache.py
├── jsonlog.py
└── detector.py
```

### Parser Contract

```python
class Parser(Protocol):
    name: str

    @classmethod
    def can_parse(cls, sample_lines: list[str]) -> bool:
        ...

    def parse(self, file_path: Path) -> Iterator[Event]:
        ...
```

### Design Decisions

- Parsers stream events one at a time.
- Memory usage stays flat.
- Malformed lines are skipped and counted.

---

## 4.3 Event Model (`src/loghound/events.py`)

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source: str
    event_type: str
    source_ip: Optional[str]
    username: Optional[str]
    raw: str
    fields: dict[str, str] = field(default_factory=dict)
```

### Design Decisions

- Immutable events prevent shared-state bugs.
- `raw` preserves evidence.
- `fields` stores parser-specific data.

---

## 4.4 Detection Engine (`src/loghound/engine.py`)

### Structure

```text
detections/
├── base.py
├── registry.py
├── ssh_brute_force.py
├── successful_after_brute.py
├── off_hours_login.py
├── web_recon.py
├── suspicious_user_agent.py
└── privilege_escalation.py
```

### Detection Contract

```python
class Detection(Protocol):
    name: str
    severity: str
    attack_id: Optional[str]

    def run(
        self,
        events: list[Event],
        config: dict,
    ) -> list[Finding]:
        ...
```

### Finding Dataclass

```python
@dataclass(frozen=True)
class Finding:
    detection_name: str
    severity: str
    timestamp: datetime
    entities: dict[str, str]
    evidence: list[str]
    attack_id: Optional[str]
    description: str
    false_positive_notes: str
```

### Engine Flow

```python
def run_engine(events: Iterator[Event], config: dict) -> list[Finding]:
    events_list = list(events)

    findings = []

    for detection in REGISTRY:
        rule_config = config["detections"].get(detection.name, {})

        if rule_config.get("enabled", True):
            findings.extend(
                detection.run(events_list, rule_config)
            )

    return sorted(
        findings,
        key=lambda f: (
            severity_rank(f.severity),
            f.timestamp
        )
    )
```

### Design Decisions

- Events are materialized once.
- Explicit registry avoids plugin magic.
- Sequential execution keeps debugging simple.

---

## 4.5 Renderers (`src/loghound/renderers/`)

### Renderers

- CLI Renderer
- TUI Renderer

Both consume:

```python
list[Finding]
```

---

## 4.6 Reporter (`src/loghound/reporting/markdown.py`)

Pure function:

```python
findings + metadata -> string
```

---

## 4.7 Configuration

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

---

# 5. Data Flow — Worked Example

```bash
loghound /var/log/auth.log --report
```

1. CLI parses arguments.
2. Parser detector selects parser.
3. Parser streams events.
4. Engine runs detections.
5. Findings are sorted.
6. Renderer outputs findings.

---

# 6. Trade-offs and Decisions Worth Defending

## Materialize events before detection

Trade-off: Higher memory usage.  
Why: Simpler detection logic.

## YAML instead of TOML/JSON

Why: Industry familiarity in security tooling.

## Explicit registry

Why: Easier debugging and predictable behavior.

## Immutable dataclasses

Why: Prevents accidental mutation bugs.

## No concurrency

Why: Simpler architecture for v1.0 scale.

---

# 7. Where to Add a New ...

## Add a new log format

1. Create parser module
2. Register parser
3. Add tests

## Add a new detection

1. Create detection module
2. Register detection
3. Add config
4. Add tests

## Add a new renderer

1. Create renderer
2. Add CLI flag

---

# 8. Testing Strategy

- Parser tests use fixture logs
- Detection tests use synthetic events
- Engine tests verify orchestration
- Renderer tests are smoke tests
- End-to-end tests validate CLI behavior

Coverage goals:

- Detections: >90%
- Parsers: >80%

---

# 9. What This Architecture Is Not

- Not a SIEM
- Not multi-host
- Not a stream processor
- Not ML-driven

---

# 10. Future Architecture

Possible future work:

- Streaming detection mode
- Sigma rule support
- Plugin discovery
- Persistent state
- Watch mode (`tail -f`)

---

# 11. Diagram

Canonical diagram lives in:

```text
docs/images/architecture.png
```

---

# 12. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 0.1 | [Date] | [You] | Initial draft alongside SRS v1.0 |
