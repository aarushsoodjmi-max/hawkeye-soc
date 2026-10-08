from __future__ import annotations

from typing import Any, Dict, List

from app.reporting.threat_intelligence import get_attack_chain_summary, get_dominant_stage


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def build_threat_profile(incident: Any) -> Dict[str, Any]:
    timeline = _get(incident, "timelineEvents", []) or []
    root = _get(incident, "rootCause", None)
    techniques: List[str] = []
    for event in timeline:
        if _get(event, "techniqueId"):
            techniques.append(str(_get(event, "techniqueId")))
        elif _get(event, "technique"):
            techniques.append(str(_get(event, "technique")))
    confidence = float(_get(root, "confidence", 0.0) or 0.0) if root else 0.0
    indicators = []
    if root and _get(root, "cveId"):
        indicators.append({"type": "cve", "value": str(_get(root, "cveId"))})
    if root and _get(root, "c2Server"):
        indicators.append({"type": "c2", "value": str(_get(root, "c2Server"))})
    return {
        "attack_chain": get_attack_chain_summary(techniques),
        "dominant_stage": get_dominant_stage(techniques),
        "indicators": indicators,
        "threat_actor": str(_get(incident, "threatActor", "Unknown Threat Actor")),
        "confidence": round(confidence, 4),
    }
