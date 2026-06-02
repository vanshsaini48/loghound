from .ssh_brute_force import SSHBruteForce
from .successful_after_brute import SuccessfulAfterBrute
from .off_hours_login import OffHoursLogin
from .web_recon import WebRecon
from .suspicious_user_agent import SuspiciousUserAgent
from .privilege_escalation import PrivilegeEscalation

# Class references, not instances. The engine instantiates per run.
REGISTRY = [
    OffHoursLogin,
    SuspiciousUserAgent,
    SSHBruteForce,
    SuccessfulAfterBrute,
    WebRecon,
    PrivilegeEscalation,
]
