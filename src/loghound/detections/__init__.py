from src.loghound.detections.ssh_brute_force import SSHBruteForce
from src.loghound.detections.successful_after_brute import SuccessfulAfterBrute
from src.loghound.detections.off_hours_login import OffHoursLogin

REGISTRY = [
    SSHBruteForce(),
    SuccessfulAfterBrute(),
    OffHoursLogin(),
]
