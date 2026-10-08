"""
Incident Builder
================
Converts entity-resolved alert clusters (as produced by
`correlation_engine.group_by_entities`) into final, structured incident
records suitable for SOC analyst review.

Pure Python + pandas. No ML, no APIs, no frontend.
"""

from __future__ import annotations

import pandas as pd

from .correlation_engine import calculate_confidence
from .timeline import create_attack_timeline, get_first_event, get_last_event

INCIDENT_ID_PREFIX = "INC"


def assign_incident_ids(count: int, prefix: str = INCIDENT_ID_PREFIX) -> list[str]:
    """Generate `count` sequential, zero-padded synthetic incident IDs.

    Example
    -------
    >>> assign_incident_ids(3)
    ['INC-0001', 'INC-0002', 'INC-0003']

    These IDs are freshly generated for each reconstructed incident and
    are independent of any pre-existing `incident_id` values on the raw
    alerts — those originals are preserved per-alert inside the
    incident's `alerts` list (see `build_incident`) for traceability.
    """
    if count < 0:
        raise ValueError("count must be >= 0")
    width = max(4, len(str(count)))
    return [f"{prefix}-{str(i).zfill(width)}" for i in range(1, count + 1)]


def _entity_summary(alerts: pd.DataFrame) -> dict:
    """Collect the distinct entities (users/devices/IPs) involved in a group."""
    return {
        "users": sorted(alerts["user"].dropna().unique().tolist()),
        "devices": sorted(alerts["device"].dropna().unique().tolist()),
        "ip_addresses": sorted(alerts["ip_address"].dropna().unique().tolist()),
    }


def build_incident(groups: list[pd.DataFrame]) -> list[dict]:
    """Build the final list of incident records from clustered alert groups.

    For each group (a cluster of correlated alerts produced by
    `correlation_engine.group_by_entities`) this assembles:
        - a fresh, sequential incident_id
        - the raw alerts belonging to it, chronologically ordered, as
          a list of dicts
        - a confidence score (0-100), via calculate_confidence
        - first_seen / last_seen timestamps, via timeline helpers
        - the distinct entities (users/devices/ips) involved

    Any pre-existing `incident_id` values on individual source alerts
    are left untouched inside each alert's own dict, so analysts can
    still trace back to prior labeling if it existed.

    Parameters
    ----------
    groups : list[pd.DataFrame]
        Alert clusters, as returned by `correlation_engine.group_by_entities`.

    Returns
    -------
    list[dict]
        One incident record per group. See module docstring / spec for shape.
    """
    if not groups:
        return []

    incident_ids = assign_incident_ids(len(groups))
    incidents = []

    for incident_id, alerts in zip(incident_ids, groups):
        alerts_sorted = alerts.sort_values("timestamp")
        incidents.append({
            "incident_id": incident_id,
            "alerts": alerts_sorted.to_dict(orient="records"),
            "confidence": calculate_confidence(alerts_sorted),
            "first_seen": get_first_event(alerts_sorted),
            "last_seen": get_last_event(alerts_sorted),
            "entities": _entity_summary(alerts_sorted),
        })

    return incidents


def summarize_incident(incident: dict) -> str:
    """Produce a short, human-readable one-paragraph summary of an incident.

    Intended for SOC analyst triage views or alert digests. Reconstructs
    the alert_type progression in chronological order using
    `timeline.create_attack_timeline`.

    Parameters
    ----------
    incident : dict
        A single incident record as produced by `build_incident`.

    Returns
    -------
    str
        Human-readable summary.
    """
    alerts = incident.get("alerts", [])
    if not alerts:
        return f"Incident {incident.get('incident_id', 'UNKNOWN')}: no alerts."

    alerts_df = pd.DataFrame(alerts)
    timeline_events = create_attack_timeline(alerts_df)
    alert_sequence = " -> ".join(evt["alert_type"] for evt in timeline_events)

    entities = incident.get("entities", {})
    users = ", ".join(entities.get("users", [])) or "unknown user"
    devices = ", ".join(entities.get("devices", [])) or "unknown device"
    ips = ", ".join(entities.get("ip_addresses", [])) or "unknown IP"

    return (
        f"Incident {incident['incident_id']} (confidence: {incident['confidence']}%): "
        f"{len(alerts)} alert(s) involving user(s) [{users}], device(s) [{devices}], "
        f"IP(s) [{ips}], spanning {incident['first_seen']} -> {incident['last_seen']}. "
        f"Attack sequence: {alert_sequence}."
    )
