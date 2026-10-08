"""
metrics.py
==========

Quantitative SOC metrics computed over *correlated incidents*.

This module makes NO assumptions about where incidents come from - it only
assumes each incident is a ``dict`` (or the whole set is a ``list[dict]``)
with a reasonably flexible schema. Every field is read defensively with
``.get()`` so missing keys degrade gracefully instead of raising.

Expected (flexible) incident shape
-----------------------------------
    {
        "incident_id": "INC-1023",
        "severity": "Critical",                 # Critical | High | Medium | Low | Informational
        "alerts": [ {...}, {...} ],              # raw alerts folded into this incident
        "detected_at": "2024-01-01T10:00:00Z",   # ISO-8601 string or datetime
        "resolved_at": "2024-01-01T10:45:00Z",   # ISO-8601 string or datetime (optional)
        "devices": ["HOST-01", "HOST-02"],
        "ips": ["10.0.0.5", "10.0.0.9"],
        "techniques": ["login anomaly", "powershell", "privilege escalation"],
    }

All functions return **plain dictionaries only** (per project requirement),
so results are trivially JSON-serializable regardless of how they are
consumed downstream.

Dependencies: pandas only (no sklearn, no network/API calls).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

import pandas as pd

IncidentList = List[Dict[str, Any]]

# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------

def _count_raw_alerts(incidents: IncidentList) -> int:
    """Sum the number of raw alerts folded into every incident."""
    total = 0
    for incident in incidents:
        alerts = incident.get("alerts") or []
        total += len(alerts)
    return total


def _to_timestamp(value: Optional[Union[str, "pd.Timestamp"]]) -> Optional[pd.Timestamp]:
    """Best-effort conversion of a timestamp-like value to pandas.Timestamp."""
    if value is None:
        return None
    ts = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(ts):
        return None
    return ts


def _resolution_minutes(incident: Dict[str, Any]) -> Optional[float]:
    """Minutes between detection and resolution for a single incident."""
    detected = _to_timestamp(incident.get("detected_at"))
    resolved = _to_timestamp(incident.get("resolved_at"))
    if detected is None or resolved is None:
        return None
    delta_minutes = (resolved - detected).total_seconds() / 60.0
    return max(delta_minutes, 0.0)


# --------------------------------------------------------------------------
# Public metrics
# --------------------------------------------------------------------------

def alert_compression_ratio(
    raw_alert_count: Optional[int] = None,
    incidents: Optional[IncidentList] = None,
) -> Dict[str, Any]:
    """
    Measure how effectively raw alerts were compressed into incidents.

    A correlation engine's main value is noise reduction: turning thousands
    of raw alerts into a handful of actionable incidents. This ratio
    quantifies that.

    Parameters
    ----------
    raw_alert_count : int, optional
        Total number of raw alerts *before* correlation. If omitted, this is
        derived by summing the "alerts" arrays nested inside each incident.
    incidents : list[dict], optional
        The correlated incidents. Required if ``raw_alert_count`` is not
        provided directly.

    Returns
    -------
    dict
        {
            "raw_alert_count": int,
            "incident_count": int,
            "compression_ratio": float,   # raw_alerts / incidents
            "alerts_per_incident": float, # same value, clearer naming
            "noise_reduction_pct": float  # % of alerts eliminated by correlation
        }
    """
    incidents = incidents or []
    incident_count = len(incidents)

    if raw_alert_count is None:
        raw_alert_count = _count_raw_alerts(incidents)

    if incident_count == 0 or raw_alert_count == 0:
        return {
            "raw_alert_count": raw_alert_count,
            "incident_count": incident_count,
            "compression_ratio": 0.0,
            "alerts_per_incident": 0.0,
            "noise_reduction_pct": 0.0,
        }

    compression_ratio = raw_alert_count / incident_count
    noise_reduction_pct = (1 - (incident_count / raw_alert_count)) * 100

    return {
        "raw_alert_count": raw_alert_count,
        "incident_count": incident_count,
        "compression_ratio": round(compression_ratio, 2),
        "alerts_per_incident": round(compression_ratio, 2),
        "noise_reduction_pct": round(noise_reduction_pct, 2),
    }


def severity_distribution(incidents: IncidentList) -> Dict[str, Any]:
    """
    Count incidents by severity and express each as a share of the total.

    Parameters
    ----------
    incidents : list[dict]
        Correlated incidents, each expected to carry a "severity" field.
        Missing/unknown severities are bucketed as "Unknown".

    Returns
    -------
    dict
        {
            "counts": {"Critical": 3, "High": 5, "Medium": 2, ...},
            "percentages": {"Critical": 27.3, "High": 45.5, ...},
            "total_incidents": int
        }
    """
    if not incidents:
        return {"counts": {}, "percentages": {}, "total_incidents": 0}

    severities = [str(i.get("severity") or "Unknown").title() for i in incidents]
    series = pd.Series(severities)

    counts = series.value_counts().to_dict()
    total = len(series)
    percentages = {k: round((v / total) * 100, 2) for k, v in counts.items()}

    return {
        "counts": counts,
        "percentages": percentages,
        "total_incidents": total,
    }


def mttr_estimate(incidents: IncidentList) -> Dict[str, Any]:
    """
    Estimate Mean Time To Resolve (MTTR) across incidents that have both a
    "detected_at" and "resolved_at" timestamp.

    Parameters
    ----------
    incidents : list[dict]

    Returns
    -------
    dict
        {
            "mttr_minutes": float,          # mean
            "median_minutes": float,
            "min_minutes": float,
            "max_minutes": float,
            "resolved_incident_count": int, # incidents with valid pairs
            "unresolved_incident_count": int
        }
    """
    resolution_times = [
        rt for rt in (_resolution_minutes(i) for i in incidents) if rt is not None
    ]

    resolved_count = len(resolution_times)
    unresolved_count = len(incidents) - resolved_count

    if resolved_count == 0:
        return {
            "mttr_minutes": 0.0,
            "median_minutes": 0.0,
            "min_minutes": 0.0,
            "max_minutes": 0.0,
            "resolved_incident_count": 0,
            "unresolved_incident_count": unresolved_count,
        }

    series = pd.Series(resolution_times)

    return {
        "mttr_minutes": round(float(series.mean()), 2),
        "median_minutes": round(float(series.median()), 2),
        "min_minutes": round(float(series.min()), 2),
        "max_minutes": round(float(series.max()), 2),
        "resolved_incident_count": resolved_count,
        "unresolved_incident_count": unresolved_count,
    }


def incident_statistics(incidents: IncidentList) -> Dict[str, Any]:
    """
    Aggregate, high-level statistics across the full incident set. Meant as
    a single "dashboard summary" call that bundles the other metrics plus a
    few extra rollups (unique devices/IPs/techniques touched).

    Parameters
    ----------
    incidents : list[dict]

    Returns
    -------
    dict
        {
            "total_incidents": int,
            "total_raw_alerts": int,
            "unique_devices": int,
            "unique_ips": int,
            "unique_techniques": int,
            "avg_alerts_per_incident": float,
            "compression": {...},          # alert_compression_ratio() output
            "severity": {...},             # severity_distribution() output
            "mttr": {...},                 # mttr_estimate() output
        }
    """
    total_incidents = len(incidents)

    all_devices = set()
    all_ips = set()
    all_techniques = set()

    for incident in incidents:
        all_devices.update(incident.get("devices") or [])
        all_ips.update(incident.get("ips") or [])
        all_techniques.update(
            t.lower() for t in (incident.get("techniques") or [])
        )

    total_raw_alerts = _count_raw_alerts(incidents)
    avg_alerts_per_incident = (
        round(total_raw_alerts / total_incidents, 2) if total_incidents else 0.0
    )

    return {
        "total_incidents": total_incidents,
        "total_raw_alerts": total_raw_alerts,
        "unique_devices": len(all_devices),
        "unique_ips": len(all_ips),
        "unique_techniques": len(all_techniques),
        "avg_alerts_per_incident": avg_alerts_per_incident,
        "compression": alert_compression_ratio(incidents=incidents),
        "severity": severity_distribution(incidents),
        "mttr": mttr_estimate(incidents),
    }
