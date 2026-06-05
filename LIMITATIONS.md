# Limitations

## Explicit Non-Goals

These are deliberate design decisions, not missing features.

- **No real-time tailing.** loghound processes bounded, offline log files. It does not `tail -f` or alert on live events.
- **No multi-host correlation.** Merging rotated logs from the same host is supported. Correlating across different hosts (e.g., matching a firewall log to an auth log on a different server) is out of scope.
- **No machine learning.** All detections are rule-based with configurable thresholds. This keeps the tool transparent and auditable.
- **No alerting.** loghound produces reports. It does not send emails, Slack messages, or webhook notifications.
- **No authentication or multi-user.** Single-user CLI tool. No RBAC, no sessions.
- **No web UI.** Terminal only (CLI + TUI).
- **No online threat intel.** IOC matching uses local files only. No API calls to VirusTotal, AbuseIPDB, etc.

## Known Constraints

- **Windows EVTX not supported (yet).** Binary parsing and Event ID mapping is planned for v2.1.
- **auditd / firewall / CSV logs not supported (yet).** Planned for v2.1.
- **GeoIP impossible-travel not supported (yet).** Requires offline GeoIP database. Planned for v2.1.
- **Time ordering assumed.** Windowed detections assume input is roughly time-ordered. This holds for single-host logs and same-host rotated log merges. Shuffled or multi-host logs may produce incorrect window calculations.
- **Ambiguous years.** Syslog timestamps lack a year field. loghound assumes the current year.
- **No Sigma rules.** Detection rules are Python modules, not Sigma YAML. Sigma import is a future goal.
- **Entity risk scoring is additive.** Risk scores grow linearly with finding count. There is no decay, normalization, or baseline comparison.

## Performance Bounds

- **Memory:** Constant with respect to input size (target < 250 MB RSS).
- **Throughput:** ~50 MB/s parse+detect on commodity hardware.
- **File size:** No hard limit. Tested with multi-gigabyte synthetic logs.

## Memory Usage

**v2.0 Behavior:** Linear memory growth (~2x input file size).

**Test Results (500 MB synthetic auth.log):**
- Peak memory: ~1 GB
- Events processed: 4.6M
- Findings detected: 864 (deduplicated)
- Parse + detect time: ~13 minutes

**Why:** Events and findings are materialized for simplicity. Entity risk scoring requires two-pass algorithm.

**Scaling:** Memory usage is O(n) where n = input size. For gigabyte-scale logs, split by day/hour first.

**Future (v2.1):** Streaming scoring with O(1) memory will require removing deduplication or implementing approximate dedup.
