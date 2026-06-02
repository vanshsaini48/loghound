"""IOC matching: flag findings with IPs in known IOC list."""
from typing import Iterable
from ..events import Finding
from .models import ScoredFinding


def match(findings: Iterable[Finding], config: dict) -> list[ScoredFinding]:
    """
    Match source_ip against IOC list.
    
    Config:
      ioc:
        list_path: "path/to/ioc_list.txt"  # one IP per line, or "default"
    
    For now, returns findings unchanged (stub).
    """
    # TODO: load IOC list from file
    result = []
    for sf in findings:
        # If not already a ScoredFinding, wrap it
        if not isinstance(sf, ScoredFinding):
            sf = ScoredFinding(finding=sf)
        result.append(sf)
    
    return result
