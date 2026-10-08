"""
risk_scoring.py
================

Weighted, rule-based (no ML) risk scoring for a single correlated incident.

Score is built from independent observable signals, each contributing a fixed
weight when present. The final score is capped at 100:

    +---------------------------+--------+
    | Signal                    | Weight |
    +---------------------------+--------+
    | Critical severity alert   |   25   |
    | Privilege escalation      |   20   |
    | Sensitive data access     |   15   |
    | Credential access         |   35   |
    | Ransomware activity       |   20   |
    | Exfiltration activity     |   20   |
    | Malware activity          |   20   |
    | Phishing activity         |   20   |
    | C2 activity               |   15   |
    | Multiple devices          |   10   |
    | Multiple source IPs       |    5   |
    +---------------------------+--------+
    | Maximum                   | capped |
    |                           | at 100 |
    +---------------------------+--------+

Dependencies: none beyond the standard library.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

WEIGHTS: Dict[str, int] = {
    "critical_alert": 25,
    "privilege_escalation": 20,
    "data_access": 15,
    "credential_access": 35,
    "ransomware_activity": 20,
    "exfiltration_activity": 20,
    "malware_activity": 20,
    "phishing_activity": 20,
    "c2_activity": 15,
    "multiple_devices": 10,
    "multiple_ips": 5,
}

# Keyword fragments (case-insensitive substring match) used to detect
# privilege-escalation and data-access techniques from an incident's
# "techniques" list. Kept intentionally small/explicit for auditability -
# extend as new detection content is onboarded.
PRIVILEGE_ESCALATION_KEYWORDS = [
    "privilege escalation",
    "token manipulation",
    "uac bypass",
    "shadow copy",
    "vssadmin",
    "t1490",
    "t1489",
]

DATA_ACCESS_KEYWORDS = [
    "data access",
    "sensitive data",
    "file access",
    "database access",
    "bulk download",
    "data staging",
    "mass file modification",
    "file extension change",
    "encryption",
]

# Risk-level thresholds (inclusive lower bound), evaluated highest-first.
RISK_LEVEL_THRESHOLDS: List[tuple] = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Informational"),
]


# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------

def _has_critical_alert(incident: Dict[str, Any]) -> bool:
    """True if the incident itself, or any nested alert, is Critical severity."""
    if str(incident.get("severity") or "").strip().lower() == "critical":
        return True
    for alert in incident.get("alerts") or []:
        if str(alert.get("severity") or "").strip().lower() == "critical":
            return True
    return False


def _techniques_lower(incident: Dict[str, Any]) -> List[str]:
    return [str(t).strip().lower() for t in (incident.get("techniques") or [])]


def _has_keyword(techniques_lower: List[str], keywords: List[str]) -> bool:
    return any(kw in tech for tech in techniques_lower for kw in keywords)


def _has_multiple_devices(incident: Dict[str, Any]) -> bool:
    return len(set(incident.get("devices") or [])) > 1


def _has_multiple_ips(incident: Dict[str, Any]) -> bool:
    return len(set(incident.get("ips") or [])) > 1


def _risk_level_for_score(score: int) -> str:
    for lower_bound, label in RISK_LEVEL_THRESHOLDS:
        if score >= lower_bound:
            return label
    return "Informational"  # unreachable safeguard


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def calculate_risk_score(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate a 0-100 risk score for a single correlated incident.

    Parameters
    ----------
    incident : dict
        Expected fields (all optional, read defensively):
            "severity"   : str                 e.g. "Critical"
            "alerts"     : list[dict]           each optionally with "severity"
            "techniques" : list[str]            e.g. ["privilege escalation", ...]
            "devices"    : list[str]
            "ips"        : list[str]

    Returns
    -------
    dict
        {
            "incident_id": str | None,
            "risk_score": int,        # 0-100
            "risk_level": str,        # Informational | Low | Medium | High | Critical
            "breakdown": {
                "critical_alert": {"triggered": bool, "points": int},
                "privilege_escalation": {"triggered": bool, "points": int},
                "data_access": {"triggered": bool, "points": int},
                "multiple_devices": {"triggered": bool, "points": int},
                "multiple_ips": {"triggered": bool, "points": int},
            }
        }
    """
    techniques_lower = _techniques_lower(incident)

    credential_signals = ("credential dumping", "credential dump", "lsass", "mimikatz", "t1003", "mfa bypass", "failed login", "impossible travel", "credential harvesting")
    ransomware_signals = ("ransomware", "ransom note", "shadow copy", "vssadmin", "mass file modification", "file extension change", "t1486", "t1490")
    exfiltration_signals = ("exfiltration", "exfiltrate", "cloud upload", "personal cloud", "bulk download", "data staging", "t1567", "t1074", "t1052")
    malware_signals = ("malware", "trojan", "process injection", "file dropped", "scheduled task", "registry persistence", "t1055", "t1105")
    phishing_signals = ("phishing", "credential harvesting", "malicious link", "attachment opened", "macro execution", "t1566")
    c2_signals = ("outbound c2", "c2 beacon", "beacon", "command and control", "dns anomaly", "t1071")
    signals = {
        "critical_alert": _has_critical_alert(incident),
        "privilege_escalation": _has_keyword(techniques_lower, PRIVILEGE_ESCALATION_KEYWORDS),
        "data_access": _has_keyword(techniques_lower, DATA_ACCESS_KEYWORDS),
        "credential_access": _has_keyword(techniques_lower, list(credential_signals)),
        "ransomware_activity": _has_keyword(techniques_lower, list(ransomware_signals)),
        "exfiltration_activity": _has_keyword(techniques_lower, list(exfiltration_signals)),
        "malware_activity": _has_keyword(techniques_lower, list(malware_signals)),
        "phishing_activity": _has_keyword(techniques_lower, list(phishing_signals)),
        "c2_activity": _has_keyword(techniques_lower, list(c2_signals)),
        "multiple_devices": _has_multiple_devices(incident),
        "multiple_ips": _has_multiple_ips(incident),
    }

    breakdown = {
        name: {
            "triggered": triggered,
            "points": WEIGHTS[name] if triggered else 0,
        }
        for name, triggered in signals.items()
    }

    raw_score = sum(item["points"] for item in breakdown.values())
    risk_score = min(raw_score, 100)  # weights already sum to 100, this is a safeguard

    return {
        "incident_id": incident.get("incident_id"),
        "risk_score": risk_score,
        "risk_level": _risk_level_for_score(risk_score),
        "breakdown": breakdown,
    }


def score_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batch convenience wrapper around ``calculate_risk_score``."""
    return [calculate_risk_score(incident) for incident in (incidents or [])]


def average_risk_score(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate risk statistics across a set of incidents - useful for a SOC
    dashboard "overall risk posture" widget.

    Returns
    -------
    dict
        {
            "average_risk_score": float,
            "highest_risk_score": int,
            "risk_level_counts": {"Critical": 2, "High": 3, ...},
            "incident_count": int,
        }
    """
    scored = score_incidents(incidents)
    if not scored:
        return {
            "average_risk_score": 0.0,
            "highest_risk_score": 0,
            "risk_level_counts": {},
            "incident_count": 0,
        }

    scores = [s["risk_score"] for s in scored]
    level_counts: Dict[str, int] = {}
    for s in scored:
        level_counts[s["risk_level"]] = level_counts.get(s["risk_level"], 0) + 1

    return {
        "average_risk_score": round(sum(scores) / len(scores), 2),
        "highest_risk_score": max(scores),
        "risk_level_counts": level_counts,
        "incident_count": len(scored),
    }
