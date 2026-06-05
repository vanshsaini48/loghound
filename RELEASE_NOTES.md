# LogHound Release Notes

## v2.0.0 — Complete (2026-06-05)

### 📊 By the Numbers
- Code: ~2,500 lines (Python)
- Tests: 92 passing, 0 failures
- Detections: 9 total (6 migrated + 3 new)
- Parsers: 5 formats supported
- Development time: 3 days

### 🎯 Features
✅ 9 detections with configurable thresholds
✅ 5 log parsers (auto-detect + override)
✅ Allowlist suppression (config-driven)
✅ Entity risk scoring (per-IP, per-user)
✅ Finding deduplication with counts
✅ IOC matching (offline, local)
✅ Time filtering (--since/--until)
✅ Multi-file merge (rotated logs)
✅ CloudTrail support + sensitive action detection

### 📤 Outputs
✅ CLI summary (risk-sorted findings)
✅ Markdown reports (ATT&CK, timeline, evidence)
✅ JSON-lines (documented schema)
✅ Interactive TUI dashboard (search, sort, pivot, export)

### 📚 Documentation
✅ docs/ARCHITECTURE.md (14 sections, streaming contract)
✅ docs/LIMITATIONS.md (non-goals, constraints)
✅ docs/json-schema.md (output format, jq examples)
✅ README.md (quick start, demo GIFs, keybindings)
✅ SRS.md (v2.0 acceptance criteria, all met)

### 🧪 Testing
✅ 92 tests passing (target: 24+)
✅ Parser tests: syslog, Apache, Nginx, JSON, CloudTrail
✅ Detection tests: streaming contract verified
✅ Triage tests: allowlist, scoring, dedup
✅ Integration tests: CLI, reporter, TUI
✅ Gigabyte test: 500 MB → 4.6M events, ~1 GB RAM

### 🎬 Demo Materials
✅ demo_automated.gif (627 KB) — automated walkthrough
✅ demo_interactive_tui.gif (1.1 MB) — interactive TUI
✅ Both embedded in README.md

---

## v2.1 Roadmap
- True O(1) memory (streaming scoring, no dedup)
- Windows EVTX parsing
- auditd/firewall/CSV parsers
- Sigma rule support
- GeoIP impossible-travel detection
