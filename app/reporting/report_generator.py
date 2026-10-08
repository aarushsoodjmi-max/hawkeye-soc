"""
report_generator.py
====================

Converts an analyzed incident (a plain Python dict produced upstream by
HawkEye's detection/correlation engine) into a structured SOC incident
report.

This module is standalone: it does not call any API, does not touch a
database, and does not depend on any other HawkEye module other than
`threat_intelligence.py` (for ATT&CK stage mapping) within this same
reporting package.

Expected (loosely-typed) input shape for `incident`
----------------------------------------------------
{
    "incident_id": "INC-1001",                      # optional, auto-generated if missing
    "title": "Compromised Employee Account",         # optional
    "description": "...",                            # optional, free text
    "affected_entities": ["user:jdoe", "host:WKS-102"],
    "events": [
        {
            "timestamp": "2026-08-01T02:14:00Z",
            "technique": "login_anomaly",
            "description": "Login from unusual geolocation"
        },
        ...
    ],
    "root_cause": "...",                              # optional override
    "confidence": 0.9                                 # optional override, 0.0-1.0
}

Only `events` materially affects scoring; all other fields are optional
and have safe defaults, so the generator degrades gracefully on sparse
input.
"""

from typing import Any, Dict, List, Optional

from . import threat_intelligence as ti

# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

# Points contributed by each ATT&CK stage present in the incident.
# Weighted toward stages that indicate deeper compromise / higher impact.
STAGE_WEIGHTS: Dict[str, int] = {
    "Initial Access": 10,
    "Execution": 12,
    "Persistence": 14,
    "Privilege Escalation": 18,
    "Credential Access": 18,
    "Lateral Movement": 18,
    "Collection": 14,
    "Exfiltration": 22,
    "Command and Control": 16,
    "Impact": 25,
    "Unclassified": 4,
}

# Points added per affected entity, capped, to reflect blast radius.
POINTS_PER_ENTITY = 2
MAX_ENTITY_BONUS = 10

RISK_LEVEL_THRESHOLDS = (
    (80, "Critical"),
    (60, "High"),
    (35, "Medium"),
    (0, "Low"),
)

RECOMMENDED_ACTIONS: Dict[str, str] = {
    "Impact": "Immediately isolate affected systems and initiate incident containment procedures.",
    "Exfiltration": "Block outbound data transfer channels and initiate a data loss review.",
    "Command and Control": "Block identified C2 infrastructure at the perimeter and isolate beaconing hosts.",
    "Lateral Movement": "Isolate affected hosts from the network and audit lateral movement paths.",
    "Credential Access": "Force an immediate password reset and revoke active sessions for affected accounts.",
    "Privilege Escalation": "Suspend the affected account and review privilege escalation paths on the host.",
    "Collection": "Review and restrict access to sensitive data repositories touched during the incident.",
    "Persistence": "Remove identified persistence mechanisms and audit scheduled tasks and run keys.",
    "Execution": "Quarantine the affected endpoint and analyze executed scripts or binaries.",
    "Initial Access": "Review and strengthen perimeter controls such as email filtering and MFA.",
    "Unclassified": "Escalate to a senior analyst for manual triage and classification.",
}


def _determine_risk_level(risk_score: int) -> str:
    """Map a numeric risk score (0-100) to a categorical risk level."""
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if risk_score >= threshold:
            return level
    return "Low"


def _compute_risk_score(stages_present: List[str], affected_entities: List[str]) -> int:
    """
    Compute a 0-100 risk score from the ATT&CK stages observed and the
    number of affected entities (blast radius).

    Args:
        stages_present: De-duplicated list of ATT&CK stages seen in the incident.
        affected_entities: List of affected entity identifiers.

    Returns:
        Integer risk score clamped to the range [0, 100].
    """
    stage_score = sum(STAGE_WEIGHTS.get(stage, STAGE_WEIGHTS["Unclassified"]) for stage in stages_present)
    entity_bonus = min(MAX_ENTITY_BONUS, POINTS_PER_ENTITY * len(affected_entities or []))
    return max(0, min(100, stage_score + entity_bonus))


def _build_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize raw incident events into a chronologically-ordered timeline,
    enriched with the ATT&CK stage for each event.

    Args:
        events: Raw event dicts, each ideally containing "timestamp",
            "technique", and "description".

    Returns:
        List of timeline entries sorted by timestamp (string sort, which
        is safe for ISO-8601 timestamps).
    """
    timeline: List[Dict[str, Any]] = []
    for event in events or []:
        technique = event.get("technique", "")
        timeline.append({
            "timestamp": event.get("timestamp", ""),
            "technique": technique,
            "attack_stage": ti.map_technique_to_stage(technique),
            "description": event.get("description", ""),
        })
    timeline.sort(key=lambda entry: entry.get("timestamp") or "")
    return timeline


def _determine_root_cause(incident: Dict[str, Any], timeline: List[Dict[str, Any]]) -> str:
    """
    Determine the root cause narrative for the incident.

    Uses an analyst-provided override if present; otherwise derives a
    simple root-cause statement from the earliest timeline event.
    """
    if incident.get("root_cause"):
        return incident["root_cause"]

    if timeline:
        first = timeline[0]
        description = first.get("description") or first.get("technique") or "an unspecified initial event"
        return f"Root cause traced to: {description} (ATT&CK stage: {first.get('attack_stage', ti.UNKNOWN_STAGE)})."

    return "Root cause could not be determined from available telemetry."


def _determine_recommended_action(dominant_stage: str) -> str:
    """Look up the recommended containment/remediation action for a stage."""
    return RECOMMENDED_ACTIONS.get(dominant_stage, RECOMMENDED_ACTIONS["Unclassified"])


def _estimate_confidence(incident: Dict[str, Any], timeline: List[Dict[str, Any]]) -> float:
    """
    Estimate analyst confidence (0.0-1.0) in the report's conclusions.

    Uses an analyst-provided override if present; otherwise derives a
    simple heuristic from the number of corroborating timeline events
    (more correlated events => higher confidence), capped at 0.99.
    """
    if incident.get("confidence") is not None:
        try:
            return round(float(incident["confidence"]), 2)
        except (TypeError, ValueError):
            pass

    event_count = len(timeline)
    if event_count == 0:
        return 0.3
    # Base confidence of 0.55, +0.08 per corroborating event, capped at 0.99.
    return round(min(0.99, 0.55 + 0.08 * event_count), 2)


def generate_incident_report(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert an analyzed incident dict into a structured SOC incident report.

    Args:
        incident: Analyzed incident data (see module docstring for shape).

    Returns:
        A dict with the following keys:
            incident_id (str), title (str), root_cause (str),
            risk_score (int, 0-100), risk_level (str: Low/Medium/High/Critical),
            affected_entities (list[str]), timeline (list[dict]),
            recommended_action (str), confidence (float, 0.0-1.0)
    """
    incident = incident or {}

    affected_entities = list(incident.get("affected_entities") or [])
    events = incident.get("events") or []

    timeline = _build_timeline(events)
    technique_keys = [event.get("technique", "") for event in events]
    stages_present = ti.map_techniques_to_stages(technique_keys)
    dominant_stage = ti.get_dominant_stage(technique_keys)

    risk_score = _compute_risk_score(stages_present, affected_entities)
    risk_level = _determine_risk_level(risk_score)

    return {
        "incident_id": incident.get("incident_id", "UNKNOWN-INCIDENT"),
        "title": incident.get("title", "Untitled Security Incident"),
        "root_cause": _determine_root_cause(incident, timeline),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "affected_entities": affected_entities,
        "timeline": timeline,
        "recommended_action": _determine_recommended_action(dominant_stage),
        "confidence": _estimate_confidence(incident, timeline),
    }
