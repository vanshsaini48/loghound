# Limitations

loghound is a focused triage tool, not a SIEM. This document lists explicit non-goals and known constraints so you know exactly what you are getting.

---

## Non-Goals

These are deliberate design decisions, not missing features:

- **Real-time log tailing.** loghound analyzes bounded log files. It does not watch live streams or replace a monitoring system.
- **Multi-file and multi-host correlation.** Each run analyzes a single file. Cross-host attack chains are out of scope.
- **Machine learning detection.** All detections are deterministic rules with configurable thresholds. No training data, no models, no black boxes.
- **Alert delivery.** No email, Slack, or webhook notifications. loghound produces reports; delivery is your problem.
- **Authentication and multi-user support.** There are no user accounts, roles, or access controls. It is a single-user CLI tool.
- **Web UI.** Terminal only. The TUI is the richest interface.
- **SIEM integrations.** No Splunk, Elastic, or QRadar connectors.
- **Ticketing and chat integrations.** No Jira, ServiceNow, or PagerDuty.
- **Windows EVTX parsing.** Only Linux auth logs and Apache/Nginx access logs are supported. EVTX is a possible v2.0 feature.
- **Encrypted or compressed logs.** Input files must be plaintext. Decompress or decrypt before feeding to loghound.

---

## Known Constraints

These are gaps in the current implementation that may be addressed in future versions:

- **No UTC normalization.** Timestamps are parsed as-is. Logs from different timezones analyzed separately will not have their times aligned. Single-host analysis is unaffected.
- **No JSON-lines parser.** The architecture supports pluggable parsers, but only syslog and Apache CLF parsers are implemented.
- **No --format override.** Log format is always auto-detected. Manual override is not yet implemented.
- **No --output directory validation.** Passing a report output path under a nonexistent directory will raise an error instead of creating the directory or printing a friendly message.
- **Ambiguous-year timestamps assume current year.** Syslog lines without a year field are assigned the current year at parse time.
- **Memory scales with event count.** Events are streamed during parsing (memory-flat), but materialized into a list before detection. Files with millions of events will consume proportional memory. The 1 GB / 500 MB target from the SRS has not been benchmarked.
- **No concurrency.** Detections run sequentially. This is a simplicity decision for v1.0 and has no practical impact at current scale.
- **Detection thresholds are tuned to test fixtures.** Real-world logs may need threshold adjustments via the config file to reduce false positives.

---

## Scale

loghound is designed for offline triage of bounded log files, roughly under 1 GB. It is not a production monitoring system and should not be deployed as one.
