from collections import defaultdict
from datetime import timedelta
from ..events import Event
from ..events import Finding


class SSHBruteForce:
    name = "ssh_brute_force"
    severity = "high"
    attack_id = "T1110"

    def run(self, events: list[Event], config: dict) -> list[Finding]:
        threshold = config.get("threshold", 5)
        window_minutes = config.get("window_minutes", 10)
        window = timedelta(minutes=window_minutes)

        # Step 1: Filter to failed SSH logins that have a source_ip
        failures = [
            e for e in events
            if (e.fields.get("process") == "sshd"
                and "Failed password" in e.fields.get("message", "")
                and e.source_ip is not None)
        ]

        # Step 2: Group failures by source IP
        by_ip = defaultdict(list)
        for e in failures:
            by_ip[e.source_ip].append(e)

        # Step 3: For each IP, check if it hit the threshold within the window
        findings = []
        for source_ip, ip_failures in by_ip.items():
            ip_failures.sort(key=lambda e: e.timestamp)

            # Sliding window: for each event, count how many fall within [event_time, event_time + window)
            for i in range(len(ip_failures)):
                window_start = ip_failures[i].timestamp
                window_end = window_start + window
                in_window = [
                    e for e in ip_failures
                    if window_start <= e.timestamp < window_end
                ]

                if len(in_window) >= threshold:
                    # Found a brute force attempt
                    finding = Finding(
                        detection_name=self.name,
                        severity=self.severity,
                        timestamp=window_start,
                        entities={"source_ip": source_ip},
                        evidence=[e.raw for e in in_window[:threshold]],
                        attack_id=self.attack_id,
                        description=f"SSH brute force from {source_ip}: {len(in_window)} failed login attempts in {window_minutes} minutes",
                        false_positive_notes="Could be a legitimate user repeatedly typing their password wrong, but 5+ attempts across multiple accounts within 10 minutes is rare and suspicious."
                    )
                    findings.append(finding)
                    break  # One finding per IP (at the first window that crosses threshold)

        return findings
