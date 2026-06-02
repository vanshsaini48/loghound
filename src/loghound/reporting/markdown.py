"""Generate professional Markdown incident reports from triage findings."""
from datetime import datetime
from ..triage.models import ScoredFinding


def generate_markdown_report(
    scored_findings: list[ScoredFinding],
    source_file: str,
    events_count: int,
) -> str:
    active = [sf for sf in scored_findings if not sf.suppressed]
    suppressed = [sf for sf in scored_findings if sf.suppressed]

    severity_counts = {}
    attack_counts = {}

    for sf in active:
        sev = sf.finding.severity.upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if sf.finding.attack_id:
            attack_id = sf.finding.attack_id
            attack_counts[attack_id] = attack_counts.get(attack_id, 0) + 1

    report_time = datetime.now().isoformat(timespec='seconds')

    lines = []
    lines.append("# Security Log Analysis Report")
    lines.append("")
    lines.append(f"**Generated:** {report_time}")
    lines.append(f"**Log File:** {source_file}")
    lines.append(f"**Total Events Processed:** {events_count}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")

    # Single summary line
    summary = f"Analyzed {events_count} events and detected {len(active)} active finding(s)"
    if suppressed:
        summary += f" ({len(suppressed)} suppressed by allowlist)"
    summary += "."
    lines.append(summary)
    lines.append("")

    if active:
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                lines.append(f"| {severity} | {count} |")
        lines.append("")

    if attack_counts:
        lines.append("## MITRE ATT&CK Summary")
        lines.append("")
        lines.append("| Technique | Findings |")
        lines.append("|-----------|----------|")

        for attack_id, count in sorted(
            attack_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            lines.append(f"| {attack_id} | {count} |")

        lines.append("")

    if active:
        lines.append("## Active Findings")
        lines.append("")
        lines.append("| # | Detection | Severity | Time | Entities | Risk |")
        lines.append("|---|-----------|----------|------|----------|------|")
        for idx, sf in enumerate(active, 1):
            entities_str = ", ".join(f"{k}: {v}" for k, v in sf.finding.entities.items())
            time_str = sf.finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            risk = sum(sf.entity_risk.values())
            lines.append(
                f"| {idx} | {sf.finding.detection_name} | {sf.finding.severity.upper()} | "
                f"{time_str} | {entities_str} | {risk} |"
            )
        lines.append("")

    if active:
        lines.append("## Detailed Findings")
        lines.append("")
        for idx, sf in enumerate(active, 1):
            lines.append(f"### {idx}. {sf.finding.detection_name} [{sf.finding.severity.upper()}]")
            lines.append("")
            if sf.finding.attack_id:
                lines.append(f"**ATT&CK Technique:** {sf.finding.attack_id}")
            else:
                lines.append("**ATT&CK Technique:** N/A")
            lines.append("")
            time_str = sf.finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"**Time:** {time_str}")
            lines.append("")
            if sf.finding.entities:
                lines.append("**Entities:**")
                for key, value in sf.finding.entities.items():
                    entity_key = f"{key}:{value}"
                    risk = sf.entity_risk.get(entity_key, 0)
                    lines.append(f"- {key}: {value} (risk: {risk})")
                lines.append("")
            lines.append("**Description:**")
            lines.append("")
            lines.append(sf.finding.description)
            lines.append("")
            if sf.ioc_hits:
                lines.append("**IOC Hits:**")
                for ioc_hit in sf.ioc_hits:
                    lines.append(f"- {ioc_hit}")
                lines.append("")
            if sf.finding.evidence:
                lines.append("**Evidence:**")
                lines.append("")
                for ev in sf.finding.evidence:
                    lines.append(f"- {ev}")
                lines.append("")
            lines.append("**False Positive Notes:**")
            lines.append("")
            lines.append(sf.finding.false_positive_notes if sf.finding.false_positive_notes else "None")
            lines.append("")
            lines.append("---")
            lines.append("")

    if suppressed:
        lines.append("## Suppressed Findings")
        lines.append("")
        lines.append("The following findings were suppressed by allowlist rules:")
        lines.append("")
        for sf in suppressed:
            lines.append(
                f"- {sf.finding.detection_name}: {sf.finding.entities} "
                f"({sf.suppression_reason})"
            )
        lines.append("")

    lines.append("## Analyst Notes")
    lines.append("")
    lines.append("*Add your analysis, context, and remediation steps below.*")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("Generated by loghound")

    return "\n".join(lines)
