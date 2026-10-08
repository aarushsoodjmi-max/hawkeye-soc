from __future__ import annotations

from typing import Any, Dict


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def assess_business_impact(incident: Any) -> Dict[str, Any]:
    assets = _get(incident, "affectedAssets", []) or []
    risk_score = int(_get(incident, "riskScore", 0) or 0)
    critical_assets = [asset for asset in assets if str(_get(asset, "criticality", "")).upper() in {"TIER 0", "TIER 1"}]
    users = {
        str(_get(alert, "user", "")).strip()
        for alert in (_get(incident, "alerts", []) or [])
        if str(_get(alert, "user", "")).strip().lower() not in {"", "unknown", "system", "none"}
    }
    return {
        "priority": "CRITICAL" if risk_score >= 80 or critical_assets else "HIGH" if risk_score >= 60 else "MEDIUM",
        "affected_asset_count": len(assets),
        "critical_asset_count": len(critical_assets),
        "estimated_users_impacted": len(users) if users else None,
        "service_disruption": "severe" if critical_assets else "moderate" if assets else "limited",
        "summary": f"{len(critical_assets)} critical asset(s) and {len(assets)} total asset(s) are in scope.",
        "data_classification": "estimated",
        "estimated_users_impacted_label": "observed_distinct_users" if users else "unavailable",
    }
