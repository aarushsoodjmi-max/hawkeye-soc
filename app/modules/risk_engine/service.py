from __future__ import annotations

from typing import Any, Dict

from app.analytics.risk_scoring import calculate_risk_score


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def score_incident_risk(incident: Any) -> Dict[str, Any]:
    payload = {
        "incident_id": str(_get(incident, "id", _get(incident, "incident_id", ""))),
        "severity": str(_get(incident, "severity", "HIGH")),
        "alerts": [
            {"severity": _get(a, "severity", "LOW"), "alert_type": _get(a, "title", "")}
            for a in (_get(incident, "alerts", []) or [])
        ],
        "devices": [
            str(_get(a, "name", _get(a, "id", ""))) for a in (_get(incident, "affectedAssets", []) or []) if _get(a, "name", _get(a, "id", ""))
        ],
        "ips": [
            str(_get(a, "ip", "")) for a in (_get(incident, "affectedAssets", []) or []) if _get(a, "ip", "")
        ],
        "techniques": [
            str(_get(e, "technique", _get(e, "techniqueId", ""))) for e in (_get(incident, "timelineEvents", []) or [])
        ],
    }
    return calculate_risk_score(payload)
