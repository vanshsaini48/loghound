from .ssh_brute_force import SSHBruteForce
from .successful_after_brute import SuccessfulAfterBrute
from .off_hours_login import OffHoursLogin
from .web_recon import WebRecon
from .suspicious_user_agent import SuspiciousUserAgent

REGISTRY = [
    SSHBruteForce(),
    SuccessfulAfterBrute(),
    OffHoursLogin(),
    WebRecon(),
    SuspiciousUserAgent(),
]