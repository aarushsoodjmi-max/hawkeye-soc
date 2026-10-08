"""
threat_intelligence.py
=======================

Lightweight, MITRE ATT&CK-style threat intelligence mapping.

This module maps internal detection technique identifiers (the short
strings that HawkEye's detection engine attaches to raw events, e.g.
"powershell_exec") to their corresponding ATT&CK *tactic* (referred to
here as "stage") names, such as "Execution" or "Privilege Escalation".

Design notes
------------
- Pure Python, standard library only. No network calls, no LLMs.
- The mapping is intentionally a simple dictionary lookup so it is fast,
  deterministic, and trivial to unit test or extend.
- Only ATT&CK *stage names* are returned - not full technique IDs
  (e.g. not "T1059") - per module requirements.
"""

from typing import Dict, List

# ---------------------------------------------------------------------------
# Internal technique identifier -> ATT&CK Tactic ("stage") name
# ---------------------------------------------------------------------------
TECHNIQUE_TO_ATTACK_STAGE: Dict[str, str] = {
    # Canonical ATT&CK technique IDs used by HawkEye timeline events.
    "t1190": "Initial Access",
    "t1059": "Execution",
    "t1059.001": "Execution",
    "t1071.001": "Command and Control",
    "t1558.003": "Credential Access",
    "t1134.001": "Privilege Escalation",
    "t1003.001": "Credential Access",
    "t1048.003": "Exfiltration",
    # Initial Access
    "login_anomaly": "Initial Access",
    "phishing_email": "Initial Access",
    "malicious_attachment": "Initial Access",
    "malicious_link": "Initial Access",
    "exploit_public_app": "Initial Access",

    # Execution
    "powershell_exec": "Execution",
    "script_execution": "Execution",
    "macro_execution": "Execution",
    "malicious_process": "Execution",

    # Persistence
    "scheduled_task": "Persistence",
    "registry_run_key": "Persistence",
    "new_user_account": "Persistence",
    "startup_folder_write": "Persistence",

    # Privilege Escalation
    "privilege_escalation": "Privilege Escalation",
    "token_manipulation": "Privilege Escalation",
    "uac_bypass": "Privilege Escalation",

    # Credential Access
    "credential_dump": "Credential Access",
    "brute_force": "Credential Access",
    "password_spray": "Credential Access",
    "lsass_access": "Credential Access",

    # Lateral Movement
    "lateral_movement": "Lateral Movement",
    "remote_service_exec": "Lateral Movement",
    "pass_the_hash": "Lateral Movement",
    "rdp_session": "Lateral Movement",

    # Collection
    "data_access": "Collection",
    "file_staging": "Collection",
    "screen_capture": "Collection",
    "sensitive_file_read": "Collection",

    # Exfiltration
    "data_exfiltration": "Exfiltration",
    "dns_tunneling": "Exfiltration",
    "cloud_upload": "Exfiltration",
    "large_data_transfer": "Exfiltration",

    # Command and Control
    "c2_beacon": "Command and Control",
    "suspicious_dns": "Command and Control",
    "unusual_outbound_connection": "Command and Control",

    # Impact
    "ransomware_activity": "Impact",
    "data_destruction": "Impact",
    "service_stop": "Impact",
    "file_encryption": "Impact",
}

UNKNOWN_STAGE = "Unclassified"

# Priority order used when a single "dominant" stage needs to be chosen
# (highest-impact stages first). Used by report_generator/executive_summary.
STAGE_PRIORITY: List[str] = [
    "Impact",
    "Exfiltration",
    "Command and Control",
    "Lateral Movement",
    "Credential Access",
    "Privilege Escalation",
    "Collection",
    "Persistence",
    "Execution",
    "Initial Access",
    UNKNOWN_STAGE,
]


def map_technique_to_stage(technique_key: str) -> str:
    """
    Map a single internal technique identifier to its ATT&CK stage name.

    Args:
        technique_key: Internal technique identifier (e.g. "powershell_exec").

    Returns:
        The ATT&CK tactic/stage name. Returns "Unclassified" if the
        technique key is empty or not recognized.
    """
    if not technique_key:
        return UNKNOWN_STAGE
    return TECHNIQUE_TO_ATTACK_STAGE.get(str(technique_key).strip().lower(), UNKNOWN_STAGE)


def map_techniques_to_stages(technique_keys: List[str]) -> List[str]:
    """
    Map a list of technique identifiers to a de-duplicated list of ATT&CK
    stage names, preserving the order in which they were first observed.

    Args:
        technique_keys: List of internal technique identifiers, typically
            in chronological order of detection.

    Returns:
        Ordered list of unique ATT&CK stage names.
    """
    stages: List[str] = []
    for key in technique_keys or []:
        stage = map_technique_to_stage(key)
        if stage not in stages:
            stages.append(stage)
    return stages


def get_attack_chain_summary(technique_keys: List[str]) -> str:
    """
    Build a human-readable ATT&CK chain string, e.g.
    "Initial Access -> Execution -> Privilege Escalation".

    Args:
        technique_keys: List of internal technique identifiers, in the
            order they were observed.

    Returns:
        Arrow-joined string of unique ATT&CK stages, in first-seen order.
    """
    stages = map_techniques_to_stages(technique_keys)
    return " -> ".join(stages) if stages else UNKNOWN_STAGE


def get_dominant_stage(technique_keys: List[str]) -> str:
    """
    Determine the single highest-priority ATT&CK stage present in a list
    of techniques, using STAGE_PRIORITY (Impact > Exfiltration > ... ).

    Useful for choosing the most urgent recommended action or headline
    risk driver for a report.

    Args:
        technique_keys: List of internal technique identifiers.

    Returns:
        The highest-priority ATT&CK stage name present, or "Unclassified"
        if none are recognized.
    """
    stages_present = set(map_techniques_to_stages(technique_keys))
    for stage in STAGE_PRIORITY:
        if stage in stages_present:
            return stage
    return UNKNOWN_STAGE
