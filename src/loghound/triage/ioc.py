"""IOC matching: flag findings with IPs in known IOC list."""
from typing import Iterable
from pathlib import Path
from .models import ScoredFinding


def _load_ioc_list(list_path: str) -> set[str]:
    """Load IOC list from file (one IP per line, # = comment)."""
    if list_path == "default":
        # Use bundled default list
        bundled = Path(__file__).parent.parent / "data" / "ioc_default.txt"
        list_path = str(bundled)
    
    ioc_set = set()
    try:
        with open(list_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ioc_set.add(line)
    except FileNotFoundError:
        # If file not found, return empty set (no IOC matches)
        pass
    
    return ioc_set


def match(findings: Iterable[ScoredFinding], config: dict) -> list[ScoredFinding]:
    """
    Match source_ip against IOC list.
    
    Config:
      ioc:
        list_path: "default" or path to custom file
        bonus: 5  # risk bonus for IOC match
    
    Adds matched IPs to ioc_hits and boosts entity risk.
    """
    list_path = config.get("list_path", "default")
    ioc_bonus = config.get("bonus", 5)
    
    ioc_set = _load_ioc_list(list_path)
    
    result = []
    for sf in findings:
        ioc_hits = list(sf.ioc_hits) if sf.ioc_hits else []
        entity_risk = dict(sf.entity_risk) if sf.entity_risk else {}
        
        # Check if source_ip is in IOC list
        source_ip = sf.finding.entities.get("source_ip")
        if source_ip and source_ip in ioc_set:
            ioc_hits.append(source_ip)
            # Boost risk for this entity
            key = f"source_ip:{source_ip}"
            entity_risk[key] = entity_risk.get(key, 0) + ioc_bonus
        
        # Create updated ScoredFinding
        result.append(ScoredFinding(
            finding=sf.finding,
            suppressed=sf.suppressed,
            suppression_reason=sf.suppression_reason,
            ioc_hits=ioc_hits,
            entity_risk=entity_risk,
        ))
    
    return result
