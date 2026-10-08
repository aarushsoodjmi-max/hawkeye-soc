"""
explainability.py
==================

Turns a list of technique/alert names attached to a correlated incident into
a human-readable narrative, e.g.:

    Input:  ["login anomaly", "powershell", "privilege escalation"]
    Output: "The incident likely began with a compromised account. PowerShell
              execution enabled privilege escalation, followed by sensitive
              data access."

This is 100% template-based (no LLM calls, no network access). It works by:

1. Mapping each technique string to a MITRE-ATT&CK-style *kill-chain stage*
   using a keyword lookup table (``TECHNIQUE_KEYWORDS``).
2. Ordering the stages that were actually detected according to a canonical
   kill-chain order (``STAGE_ORDER``).
3. Weaving the detected stages into a short narrative using fixed sentence
   templates.
4. Optionally naming the *typical next stage* an analyst would expect given
   the last observed stage (``TYPICAL_NEXT_STAGE``) - this is a well known
   SOC heuristic (e.g. "privilege escalation is typically followed by data
   collection") and is clearly separated from *detected* stages in the
   structured output so callers never confuse inference with evidence.

Dependencies: none beyond the standard library.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# Kill-chain stage ordering
# --------------------------------------------------------------------------

STAGE_ORDER: List[str] = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

# What an analyst would typically expect to see *next*, given the last
# observed stage. Used only to add a plausible closing clause - never
# reported as a detected fact.
TYPICAL_NEXT_STAGE: Dict[str, str] = {
    "initial_access": "execution",
    "execution": "persistence",
    "persistence": "privilege_escalation",
    "privilege_escalation": "collection",
    "defense_evasion": "credential_access",
    "credential_access": "lateral_movement",
    "discovery": "lateral_movement",
    "lateral_movement": "collection",
    "collection": "exfiltration",
    "command_and_control": "exfiltration",
    "exfiltration": "impact",
}

# Generic phrase used for a stage when it has no specific matched technique
# detail (e.g. when it is only referenced as a "typical next stage").
STAGE_DEFAULT_DETAIL: Dict[str, str] = {
    "initial_access": "initial access to the environment",
    "execution": "malicious code execution",
    "persistence": "the establishment of persistence",
    "privilege_escalation": "privilege escalation",
    "defense_evasion": "defense evasion",
    "credential_access": "credential theft",
    "discovery": "internal reconnaissance",
    "lateral_movement": "lateral movement across the network",
    "collection": "sensitive data access",
    "command_and_control": "command-and-control communication",
    "exfiltration": "data exfiltration",
    "impact": "operational impact (e.g. ransomware or data destruction)",
}

# --------------------------------------------------------------------------
# Technique / alert-name -> (stage, human-readable detail) lookup table.
#
# Matching is done as a case-insensitive substring check against the raw
# technique/alert string, so keys do not need to match incoming strings
# exactly. Add new keywords here as new detection content is onboarded -
# no code changes required elsewhere.
# --------------------------------------------------------------------------

TECHNIQUE_KEYWORDS: Dict[str, Tuple[str, str]] = {
    # initial_access
    "login anomaly": ("initial_access", "a compromised account"),
    "impossible travel": ("initial_access", "an impossible-travel login anomaly"),
    "brute force": ("initial_access", "a brute-forced credential"),
    "credential stuffing": ("initial_access", "credential stuffing against an exposed account"),
    "phishing": ("initial_access", "a successful phishing lure"),
    "malicious login": ("initial_access", "a compromised account"),
    "exploit public": ("initial_access", "exploitation of a public-facing vulnerability"),
    "initial access artifact": ("initial_access", "suspicious initial access artifact execution"),
    "initial access": ("initial_access", "initial access artifact execution"),
    "t1204": ("initial_access", "untrusted artifact execution"),

    # execution
    "powershell": ("execution", "PowerShell execution"),
    "cmd.exe": ("execution", "suspicious command-line execution"),
    "command line": ("execution", "suspicious command-line execution"),
    "script execution": ("execution", "malicious script execution"),
    "macro": ("execution", "malicious macro execution"),
    "wmi": ("execution", "WMI-based execution"),
    "t1059": ("execution", "suspicious command-line / script execution"),

    # persistence
    "scheduled task": ("persistence", "a malicious scheduled task"),
    "startup folder": ("persistence", "a startup-folder persistence mechanism"),
    "registry run key": ("persistence", "a registry-based persistence mechanism"),
    "new service": ("persistence", "a malicious service installation"),
    "t1053": ("persistence", "scheduled task persistence"),
    "t1547": ("persistence", "boot or logon autostart persistence"),

    # privilege_escalation
    "privilege escalation": ("privilege_escalation", "privilege escalation"),
    "token manipulation": ("privilege_escalation", "access token manipulation"),
    "uac bypass": ("privilege_escalation", "a UAC bypass"),
    "privilege use": ("privilege_escalation", "elevated privilege token usage"),

    # defense_evasion
    "defense evasion": ("defense_evasion", "defense evasion techniques"),
    "disable security": ("defense_evasion", "the disabling of security controls"),
    "disabled security": ("defense_evasion", "the disabling of security controls"),
    "log clearing": ("defense_evasion", "clearing of security event logs"),
    "obfuscat": ("defense_evasion", "obfuscated payload delivery"),
    "shadow copy": ("defense_evasion", "Volume Shadow Copy deletion"),
    "backup service": ("defense_evasion", "disabling of backup services"),
    "t1490": ("defense_evasion", "inhibition of system recovery and shadow copy deletion"),
    "t1489": ("defense_evasion", "disabling critical backup services"),

    # credential_access
    "credential access": ("credential_access", "credential access activity"),
    "credential dump": ("credential_access", "credential dumping"),
    "mimikatz": ("credential_access", "credential theft via Mimikatz"),
    "password spray": ("credential_access", "a password spraying attack"),
    "lsass": ("credential_access", "LSASS memory access consistent with credential theft"),
    "t1003": ("credential_access", "credential dumping"),

    # discovery
    "network scan": ("discovery", "internal network scanning"),
    "reconnaissance": ("discovery", "internal reconnaissance"),
    "account discovery": ("discovery", "account enumeration"),
    "t1046": ("discovery", "network service discovery scan"),

    # lateral_movement
    "lateral movement": ("lateral_movement", "lateral movement across the network"),
    "remote desktop": ("lateral_movement", "lateral movement via Remote Desktop"),
    "psexec": ("lateral_movement", "lateral movement via PsExec"),
    "pass the hash": ("lateral_movement", "a pass-the-hash attack enabling lateral movement"),
    "smb": ("lateral_movement", "lateral movement over SMB"),
    "lateral encryption": ("lateral_movement", "lateral encryption spread across network shares"),
    "lateral spread": ("lateral_movement", "lateral spread attempt"),
    "t1021": ("lateral_movement", "lateral propagation over remote services"),

    # collection
    "data access": ("collection", "sensitive data access"),
    "sensitive data": ("collection", "sensitive data access"),
    "file access": ("collection", "access to sensitive files"),
    "database access": ("collection", "access to a sensitive database"),
    "bulk download": ("collection", "bulk data collection"),
    "data staging": ("collection", "data staging for exfiltration"),

    # command_and_control
    "command and control": ("command_and_control", "command-and-control communication"),
    "c2 beacon": ("command_and_control", "command-and-control beaconing"),
    "beacon": ("command_and_control", "command-and-control beaconing"),
    "dns tunneling": ("command_and_control", "DNS-tunneled command-and-control traffic"),
    "outbound c2": ("command_and_control", "outbound C2 communication"),
    "c2 confirmation": ("command_and_control", "C2 confirmation beaconing"),
    "t1071": ("command_and_control", "application-layer C2 beaconing"),

    # exfiltration
    "exfiltration": ("exfiltration", "data exfiltration"),
    "large data transfer": ("exfiltration", "a large outbound data transfer consistent with exfiltration"),
    "cloud upload": ("exfiltration", "outbound upload to an external cloud service"),
    "personal cloud": ("exfiltration", "upload to personal cloud storage"),

    # impact
    "ransomware": ("impact", "ransomware deployment"),
    "encryption": ("impact", "file encryption consistent with ransomware impact"),
    "data destruction": ("impact", "destructive data-wiping activity"),
    "mass file modification": ("impact", "mass file modification and encryption"),
    "file extension change": ("impact", "widespread file extension renaming"),
    "ransom note": ("impact", "ransom note deployment"),
    "t1486": ("impact", "data encrypted for impact"),
    "t1491": ("impact", "ransom note dropped for impact"),
}


# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------

def _sentence_case(text: str) -> str:
    """Uppercase only the first character, preserving the rest verbatim.

    Using str.capitalize() would lowercase internal capitals (e.g. turning
    "PowerShell execution" into "Powershell execution"), which is wrong for
    technique names with intentional internal capitalization.
    """
    if not text:
        return text
    return text[0].upper() + text[1:]


def _match_technique(technique: str) -> Optional[Tuple[str, str]]:
    """Match a single technique/alert string to (stage, detail)."""
    low = technique.strip().lower()
    if not low:
        return None
    # Check longer keywords first so more specific phrases win
    # (e.g. "credential dump" before a hypothetical shorter "dump").
    for keyword in sorted(TECHNIQUE_KEYWORDS, key=len, reverse=True):
        if keyword in low or low in keyword:
            return TECHNIQUE_KEYWORDS[keyword]
    return None


def _map_techniques_to_stages(
    techniques: List[str],
) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    Map raw technique strings to kill-chain stages.

    Returns
    -------
    (stage_details, unrecognized)
        stage_details : stage -> list of unique human-readable details
        unrecognized  : techniques that matched no known keyword
    """
    stage_details: Dict[str, List[str]] = {}
    unrecognized: List[str] = []

    for tech in techniques:
        match = _match_technique(tech)
        if match is None:
            unrecognized.append(tech)
            continue
        stage, detail = match
        bucket = stage_details.setdefault(stage, [])
        if detail not in bucket:
            bucket.append(detail)

    return stage_details, unrecognized


def _ordered_stage_details(stage_details: Dict[str, List[str]]) -> Tuple[List[str], List[str]]:
    """Return (ordered_stages, ordered_details) following STAGE_ORDER."""
    ordered_stages = [s for s in STAGE_ORDER if s in stage_details]
    ordered_details = [" and ".join(stage_details[s]) for s in ordered_stages]
    return ordered_stages, ordered_details


def _build_narrative(
    ordered_stages: List[str],
    ordered_details: List[str],
    unrecognized: Optional[List[str]] = None,
) -> Tuple[str, Optional[str]]:
    """
    Compose the final narrative string.

    Returns
    -------
    (narrative_text, predicted_next_stage_or_None)
    """
    if not ordered_stages:
        if unrecognized:
            tech_sample = ", ".join(str(t) for t in unrecognized[:3])
            return (
                f"The incident exhibited malicious activity involving {tech_sample}, indicating an active attack chain requiring analyst investigation.",
                None,
            )
        return (
            "No recognizable attack-chain techniques were found in the "
            "supplied indicators, so no narrative could be generated.",
            None,
        )

    if len(ordered_stages) == 1:
        narrative = (
            f"The incident likely began with {ordered_details[0]}, with no "
            "further attack-chain stages detected in the available telemetry."
        )
        return narrative, None

    # Sentence 1: how it started.
    sentence_one = f"The incident likely began with {ordered_details[0]}."

    # Remaining detected stages/details after the opening one.
    remaining_stages = ordered_stages[1:]
    remaining_details = ordered_details[1:]

    # Optionally append the analyst's expected "typical next stage" if the
    # last detected stage implies one that was not itself already observed.
    predicted_stage = TYPICAL_NEXT_STAGE.get(remaining_stages[-1])
    if predicted_stage and predicted_stage not in ordered_stages:
        remaining_stages = remaining_stages + [predicted_stage]
        remaining_details = remaining_details + [STAGE_DEFAULT_DETAIL[predicted_stage]]
    else:
        predicted_stage = None

    if len(remaining_details) == 1:
        sentence_two = f"{_sentence_case(remaining_details[0])} was the only further stage observed."
    else:
        head, *tail = remaining_details
        sentence_two = f"{_sentence_case(head)} enabled {tail[0]}"
        for extra in tail[1:]:
            sentence_two += f", followed by {extra}"
        sentence_two += "."

    narrative = f"{sentence_one} {sentence_two}"
    return narrative, predicted_stage


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def generate_explanation(techniques: List[str]) -> str:
    """
    Generate a single human-readable narrative string for a list of
    technique/alert names attached to one incident.

    Parameters
    ----------
    techniques : list[str]
        e.g. ["login anomaly", "powershell", "privilege escalation"]

    Returns
    -------
    str
        A short, template-generated narrative describing the likely attack
        progression.
    """
    stage_details, unrecognized = _map_techniques_to_stages(techniques or [])
    ordered_stages, ordered_details = _ordered_stage_details(stage_details)
    narrative, _predicted = _build_narrative(ordered_stages, ordered_details, unrecognized=unrecognized)
    return narrative


def explain_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full structured explanation for a single incident dict.

    Parameters
    ----------
    incident : dict
        Expected to contain a "techniques" list (see metrics.py for the
        broader incident schema). Missing/empty lists are handled safely.

    Returns
    -------
    dict
        {
            "incident_id": str | None,
            "narrative": str,                  # human-readable explanation
            "detected_stages": [str, ...],      # kill-chain stages actually observed, ordered
            "predicted_next_stage": str | None, # heuristic guess, NOT a detection
            "unrecognized_techniques": [str, ...]  # inputs that matched no keyword
        }
    """
    techniques = incident.get("techniques") or []
    stage_details, unrecognized = _map_techniques_to_stages(techniques)
    ordered_stages, ordered_details = _ordered_stage_details(stage_details)
    narrative, predicted_stage = _build_narrative(ordered_stages, ordered_details, unrecognized=unrecognized)

    return {
        "incident_id": incident.get("incident_id"),
        "narrative": narrative,
        "detected_stages": ordered_stages,
        "predicted_next_stage": predicted_stage,
        "unrecognized_techniques": unrecognized,
    }


def explain_incidents(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Batch convenience wrapper around ``explain_incident``."""
    return [explain_incident(incident) for incident in (incidents or [])]
