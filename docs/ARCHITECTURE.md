# Architecture — loghound (v2.0)

**Status:** Living document. Updated as design decisions evolve.
**Audience:** The developer (you), future contributors, and reviewers.
**Related:** `SRS.md` for the formal requirements this architecture implements.
**Supersedes:** Architecture v0.1 (drafted alongside SRS v1.0).

---

# 1. Purpose of This Document

The SRS describes *what* loghound does. This describes *how* it's built and what the boundaries between components are.

v2.0's central change is structural: detections no longer run over a fully materialized list of events. They run **as the events stream past**, holding only bounded state. This makes the streaming principle (P4) true instead of aspirational, and it's what lets the tool handle gigabyte logs in constant memory.

---

# 2. Guiding Principles

## P1. One thing at a time, well
Each module has one responsibility. A parser parses; a detection detects; a renderer renders. This makes every piece independently testable and replaceable.

## P2. Data, not state — *with bounded exceptions*
The system is a pipeline of transformations over values (`Event`, `Finding`). v2.0 introduces one deliberate exception: streaming detections hold **bounded, explicitly-scoped** state (sliding windows, per-entity counters). This state is internal to a detection, never shared, and never grows with file size.

## P3. Configuration, not code
Thresholds, business hours, allowlists, and IOC sources live in YAML. This separates security policy from engineering — the same code serves different organizations with different policies.

## P4. Streaming, not loading — *now enforced*
The system reads logs line-by-line and processes events one at a time. **Nothing holds the whole file or the whole event set in memory.** In v1.0 the engine violated this by calling `list(events)`; v2.0 removes that. This is the headline change.

## P5. Fail loudly on bugs, gracefully on data
Malformed lines are counted and skipped. Bugs crash with a clear traceback. Never silently swallow exceptions.

## P6. Test the contract, not the implementation
Tests exercise public interfaces — including the streaming detection contract.

## P7. Useful beats complete *(new in v2.0)*
A triage tool's value is in *reducing* what an analyst must read. Scoring, deduplication, and suppression are first-class, not afterthoughts.

---

# 3. High-Level Architecture

```text
+----------------------+
| Input file(s)        |  plain or .gz, one or many (same host)
+----------+-----------+
           |
           v
+----------------------+   Stage 1: Ingestion (streaming)
| Parser Layer         | - per-file format detection
|                      | - gzip-transparent, lazy line read
|                      | - multi-file time-ordered merge
+----------+-----------+
           | yields Event objects, one at a time, UTC-normalized
           v
+----------------------+   Stage 2: Detection (streaming, stateful)
| Detection Engine     | - each detection: process(event) + finalize()
|                      | - bounded per-entity state, evicted by window
+----------+-----------+
           | emits Finding objects
           v
+----------------------+   Stage 3: Enrichment / Scoring / Dedup
| Triage Layer         | - allowlist suppression
|                      | - IOC matching
|                      | - per-entity risk scoring
|                      | - dedup/aggregate repeated findings
+----------+-----------+
           | list[ScoredFinding], ranked
           v
+--------------------------------------------+ Stage 4: Presentation
v                    v                        v
+-----------+   +-----------+          +-----------+
| Dashboard |   | Markdown  |          | JSON      |
| TUI       |   | Reporter  |          | Reporter  |
+-----------+   +-----------+          +-----------+
```

The key boundaries:
- New **formats** plug in at the parser layer.
- New **detections** plug in at the engine layer via the streaming contract.
- New **enrichments** plug in at the triage layer.
- New **outputs** plug in at the renderer layer.

---

# 4. Component Breakdown

## 4.1 CLI Layer (`src/loghound/__main__.py`)
Parses arguments (including `--format`, `--json`, `--since`, `--until`, `--ioc-file`, multiple paths/globs), loads config, wires the streaming pipeline, dispatches to a renderer, returns exit codes. No business logic.

## 4.2 Parser Layer (`src/loghound/parsers/`)

```text
parsers/
├── syslog.py        # Linux auth logs
├── apache.py        # Apache Common/Combined Log Format
├── nginx.py         # Nginx access logs
├── jsonlog.py       # JSON-lines logs
├── cloudtrail.py    # AWS CloudTrail JSON (bulk + streaming)
├── reader.py        # gzip-transparent, lazy line reader
├── merge.py         # multi-file time-ordered merge
└── detector.py      # format auto-detection
```

### Parser Contract

```python
def can_parse(sample_lines: list[str]) -> bool: ...
def parse_file(file_path: Path, show_progress: bool = False) -> Iterator[Event]: ...
```

### Design Decisions
- Parsers consume line iterators via `smart_open`, so gzip reader and multi-file merger sit upstream.
- Apache and Nginx share CLF base logic.
- Malformed lines are skipped and counted.
- Parsers yield lazily (one event at a time) — required for P4.
- CloudTrail supports both bulk export (pretty-printed JSON with `Records` array) and streaming format (one JSON object per line). Extracts usernames from ARNs.

## 4.3 Event Model (`src/loghound/events.py`)

```python
@dataclass(frozen=True)
class Event:
    timestamp: datetime          # UTC, tz-aware
    source: str                  # e.g. "syslog", "cloudtrail"
    event_type: str
    source_ip: Optional[str]
    username: Optional[str]
    raw: str
    fields: dict[str, str] = field(default_factory=dict)
```

### Design Decision — flat model + `fields` dict
CloudTrail (nested API actions) doesn't map cleanly onto `source_ip / username / event_type`. **Decision: keep the flat model and push source-specific data into `fields`** (e.g., `fields["event_name"]="CreateAccessKey"`). Detections that need cloud data read from `fields` explicitly.

## 4.4 Detection Engine (`src/loghound/engine.py`)

### The streaming contract (v2.0 redesign)

```python
class Detection(Protocol):
    name: str
    severity: str
    attack_id: Optional[str]

    def process(self, event: Event) -> Iterable[Finding]: ...
    def finalize(self) -> Iterable[Finding]: ...
```

Each detection is instantiated per run, holds bounded internal state, emits findings as soon as a pattern completes (or at `finalize()` for end-of-stream cases).

### Detection Registry

```text
detections/
├── ssh_brute_force.py          # 5+ failed logins per IP in window
├── successful_after_brute.py   # Success after brute force threshold
├── off_hours_login.py          # Login outside business hours
├── web_recon.py                # 50+ 4xx responses per IP in window
├── suspicious_user_agent.py    # Scanner user agents
├── privilege_escalation.py     # sudo failures/first-time sudo
├── password_spraying.py        # One IP, many usernames
├── new_ip_for_user.py          # Login from new IP for known user
└── cloudtrail_sensitive.py     # Sensitive AWS API calls
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

## 4.5 Triage Layer (`src/loghound/triage/`) — new in v2.0

```text
triage/
├── pipeline.py      # orchestrates all stages
├── models.py        # ScoredFinding dataclass
├── allowlist.py     # suppress/downgrade by IP/user
├── ioc.py           # match source_ip against local IOC list
├── scoring.py       # per-entity risk scoring (two-pass)
└── aggregate.py     # dedup repeated findings into counted findings
```

Pipeline: `allowlist → scoring → IOC → aggregate`

```python
@dataclass(frozen=True)
class ScoredFinding:
    finding: Finding
    suppressed: bool = False
    suppression_reason: str | None = None
    ioc_hits: list[str] = field(default_factory=list)
    entity_risk: dict[str, int] = field(default_factory=dict)
    count: int = 1
```

## 4.6 Dashboard TUI (`src/loghound/renderers/tui.py`)
- **Summary panel:** event count, finding count, suppressed count, severity tallies, top entities by risk, activity sparkline.
- **Findings list:** sortable by risk/time/severity (press `s`).
- **Detail panel:** full finding with evidence, ATT&CK ID, enrichment status.
- **Live search** (`/`): filters findings as the user types.
- **Pivot** (`p`): show all findings and raw events for selected entity.
- **Export** (`e`): write Markdown report from TUI.
- **Help overlay** (`?`): keybinding reference.

## 4.7 Reporters (`src/loghound/reporting/`)
- `markdown.py` — findings + metadata → Markdown with executive summary, ATT&CK summary, investigation timeline, detailed findings.
- `json_report.py` — findings + metadata → JSON Lines with documented, stable schema (see `docs/json-schema.md`).

## 4.8 Configuration

```yaml
business_hours: { start: "08:00", end: "19:00", timezone: "UTC" }

allowlist:
  ips: ["10.0.0.5"]
  users: ["backup-svc"]

ioc:
  list_path: "default"

scoring:
  severity_weights: { critical: 10, high: 4, medium: 2, low: 1 }
  ioc_bonus: 5

detections:
  ssh_brute_force: { enabled: true, threshold: 5, window_minutes: 10 }
  password_spraying: { enabled: true, distinct_users: 10, window_minutes: 15 }
  off_hours_login: { enabled: true }
  cloudtrail_sensitive: { enabled: true }
```

---

# 5. Data Flow — Worked Example

```bash
loghound auth.log* --since "2026-06-01" --json -o findings.jsonl
```

1. CLI expands the glob, parses flags.
2. Reader opens each file (gzip-transparent); merge layer interleaves them in time order; `--since` filters early.
3. Detector picks the syslog parser; it yields UTC events lazily.
4. Engine streams events through every detection; findings emerge mid-stream and at finalize.
5. Triage layer: allowlist suppresses, IOC matches, scoring aggregates risk, dedup collapses repeats.
6. JSON reporter writes ranked findings to `findings.jsonl`.

Memory stays flat throughout.

---

# 6. Trade-offs and Decisions Worth Defending

| Decision | Trade-off | Why |
|----------|-----------|-----|
| Streaming detections | Harder detection code (stateful, windowed) | Constant memory; handles real log sizes |
| Flat Event model + `fields` | Detections must know field keys | Avoids schema change rippling through codebase |
| Triage as a separate layer | Extra pipeline stage | Keeps detections single-purpose (P1); scoring/dedup reused across outputs |
| No concurrency | Can't use multiple cores | Single streaming pass is fast enough; far easier to reason about |
| Two-pass risk scoring | Must materialize findings before scoring | Correct entity-level aggregation requires seeing all findings |

---

# 7. Where to Add a New ...

| Addition | Steps |
|----------|-------|
| **Log format** | Add parser with `can_parse`/`parse_file`, register in detector.py, add fixtures |
| **Detection** | Add module with `process`/`finalize`, register in `__init__.py`, add config + tests |
| **Enrichment** | Add transformation in `triage/`, wire into pipeline |
| **Output** | Add reporter/renderer consuming `list[ScoredFinding]`, add CLI flag |

---

# 8. Testing Strategy

- **92 tests passing, 0 failures** as of v2.0.0.
- Parser tests use fixture logs (plain, gzipped, multi-file same-host set, CloudTrail bulk JSON).
- Detection tests drive the **streaming contract** with synthetic event sequences (positive + negative each).
- Triage tests cover allowlist suppression, scoring math, IOC matching, and dedup.
- CloudTrail tests: 12 parser + 8 detection = 20 tests.
- Renderer/reporter tests are smoke + schema-validation (JSON).
- End-to-end tests validate CLI behavior and exit codes.

Coverage: detections > 90%, parsers > 80%, triage > 90%.

---

# 9. What This Architecture Is Not

Not a SIEM. Not multi-**host** correlation (same-host merge only). Not a live stream processor (offline, bounded files). Not ML-driven. Not an alerting system.

---

# 10. Future Architecture (v2.1+)

EVTX parsing; auditd/firewall/CSV parsers; offline GeoIP for impossible-travel; Sigma rule import; concurrency for multi-core throughput; watch mode (`tail -f`).

---

# 11. Revision History

| Version | Date | Author | Changes |
|---|---|---|---|
| 0.1 | 2026-05-28 | Vansh Saini | Initial draft alongside SRS v1.0 |
| 2.0 | 2026-06-05 | Vansh Saini | Streaming detection contract; gzip + multi-file reader/merger; CloudTrail parser; triage layer (allowlist, IOC, scoring, dedup); JSON reporter; dashboard TUI with search/sort/pivot/sparkline. 9 detections. 92 tests. |
