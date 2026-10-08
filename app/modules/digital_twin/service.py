from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def build_digital_twin_snapshot(incident: Any, reason: str = "state_change") -> Dict[str, Any]:
    kg = _get(incident, "knowledgeGraph", {}) or {}
    return {
        "incident_id": str(_get(incident, "id", _get(incident, "incident_id", ""))),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "reason": reason,
        "status": str(_get(incident, "status", "ACTIVE")),
        "risk_level": str(_get(incident, "riskLevel", "UNKNOWN")),
        "risk_score": int(_get(incident, "riskScore", 0) or 0),
        "asset_states": [
            {
                "asset_id": str(_get(asset, "id", _get(asset, "name", ""))),
                "status": str(_get(asset, "status", "UNKNOWN")),
                "criticality": str(_get(asset, "criticality", "UNKNOWN")),
            }
            for asset in (_get(incident, "affectedAssets", []) or [])
        ],
        "temporal_relationships": len(kg.get("relationships", []) or []),
    }
