from collections import defaultdict
from datetime import timedelta
from src.loghound.events import Event
from src.loghound.findings import Finding


class SuccessfulAfterBrute:
    name = "successful_after_brute"
    severity = "critical"
    attack_id = "T1110"

    def run(self, events: list[Event], config: dict) -> list[Finding]:
        threshold = config.get("threshold", 5)
        lookback_minutes = config.get("lookback_minutes", 60)
        lookback = timedelta(minutes=lookback_minutes)

        # Step 1: Collect failed SSH logins, grouped by source IP
        failures_by_ip = defaultdict(list)
        for e in events:
            if (e.fields.get("process") == "sshd"
                    and "Failed password" in e.fields.get("message", "")
                    and e.source_ip is not None):
                failures_by_ip[e.source_ip].append(e)

        # Step 2: Collect successful SSH logins, sorted by time
        successes = [
            e for e in events
            if (e.fields.get("process") == "sshd"
                and "Accepted password" in e.fields.get("message", "")
                and e.source_ip is not None)
        ]
        successes.sort(key=lambda e: e.timestamp)

        # Step 3: For each success, did this IP rack up >= threshold failures
        #         in the lookback window just before it?
        findings = []
        flagged_ips = set()
        for success in successes:
            source_ip = success.source_ip
            if source_ip in flagged_ips:
                continue  # one finding per IP
            window_start = success.timestamp - lookback
            prior_failures = [
                e for e in failures_by_ip.get(source_ip, [])
                if window_start <= e.timestamp < success.timestamp
            ]
            if len(prior_failures) >= threshold:
                finding = Finding(
                    detection_name=self.name,
                    severity=self.severity,
                    timestamp=success.timestamp,
                    entities={"source_ip": source_ip},
                    evidence=[e.raw for e in prior_failures[:threshold]] + [success.raw],
                    attack_id=self.attack_id,
                    description=f"Successful SSH login from {source_ip} after {len(prior_failures)} failed attempts in the previous {lookback_minutes} minutes — possible successful brute force",
                    false_positive_notes="A user who forgot their password, retried several times, then succeeded could trigger this. Risk is higher when the failures span multiple usernames or come from an unfamiliar IP."
                )
                findings.append(finding)
                flagged_ips.add(source_ip)
        return findings