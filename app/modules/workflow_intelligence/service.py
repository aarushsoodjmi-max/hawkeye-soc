from __future__ import annotations

from typing import Any, Dict, List


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def build_workflow_intelligence(incident: Any) -> Dict[str, Any]:
    risk_score = int(_get(incident, "riskScore", 0) or 0)
    threat = _get(incident, "threatIntelligence", {}) or {}
    dominant_stage = str(threat.get("dominant_stage", "Unclassified"))
    actions: List[str] = []
    if risk_score >= 80:
        actions.extend(["isolate_device", "disable_user"])
    if dominant_stage in {"Exfiltration", "Impact", "Command and Control"}:
        actions.append("block_ip")
    actions.append("create_ticket")
    return {
        "queue": "priority" if risk_score >= 80 else "standard",
        "recommended_actions": list(dict.fromkeys(actions)),
        "human_approval_required": True,
        "status": "READY_FOR_REVIEW",
    }
