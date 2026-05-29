from datetime import time
from src.loghound.events import Event
from src.loghound.findings import Finding

class OffHoursLogin:
    name = "off_hours_login"
    severity = "medium"
    attack_id = "T1078"

    def run(self, events: list[Event], config: dict) -> list[Finding]:
        # Extract business hours from config
        business_hours_config = config.get("business_hours", {})
        start_str = business_hours_config.get("start", "08:00")
        end_str = business_hours_config.get("end", "19:00")
        
        # Parse start and end times
        start_time = self._parse_time(start_str)
        end_time = self._parse_time(end_str)
        
        # Filter to successful SSH logins
        successes = [
            e for e in events
            if (e.fields.get("process") == "sshd"
                and "Accepted password" in e.fields.get("message", "")
                and e.source_ip is not None)
        ]
        
        # Check each success against business hours
        findings = []
        for e in successes:
            event_time = e.timestamp.time()
            if not (start_time <= event_time < end_time):
                # Outside business hours
                finding = Finding(
                    detection_name=self.name,
                    severity=self.severity,
                    timestamp=e.timestamp,
                    entities={"username": e.username or "unknown", "source_ip": e.source_ip},
                    evidence=[e.raw],
                    attack_id=self.attack_id,
                    description=f"SSH login from {e.source_ip} outside business hours ({start_str}–{end_str})",
                    false_positive_notes="Off-hours logins can be legitimate for on-call staff, developers in different timezones, or automated processes. Cross-reference with known on-call schedules."
                )
                findings.append(finding)
        
        return findings
    
    def _parse_time(self, time_str: str) -> time:
        """Parse 'HH:MM' string to time object."""
        h, m = map(int, time_str.split(":"))
        return time(h, m)