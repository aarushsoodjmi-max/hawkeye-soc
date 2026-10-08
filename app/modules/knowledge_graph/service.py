from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_incident_knowledge_graph(incident: Any) -> Dict[str, Any]:
    incident_id = str(_get(incident, "id", _get(incident, "incident_id", "")))
    valid_from = _get(incident, "detectedAt", None) or _now()
    nodes: List[Dict[str, Any]] = [{"id": incident_id, "type": "incident"}]
    relationships: List[Dict[str, Any]] = []

    root = _get(incident, "rootCause", None)
    compromised_account = str(_get(root, "compromisedAccount", "")).strip() if root else ""
    c2 = str(_get(root, "c2Server", "")).strip() if root else ""
    if compromised_account:
        nodes.append({"id": compromised_account, "type": "identity"})
        relationships.append({
            "source": incident_id,
            "target": compromised_account,
            "relationship_type": "targets_identity",
            "valid_from": valid_from,
            "valid_to": None,
            "confidence": float(_get(root, "confidence")) if _get(root, "confidence") is not None else 0.0,
        })
    if c2:
        nodes.append({"id": c2, "type": "indicator"})
        relationships.append({
            "source": incident_id,
            "target": c2,
            "relationship_type": "communicates_with",
            "valid_from": valid_from,
            "valid_to": None,
            "confidence": float(_get(root, "confidence")) if _get(root, "confidence") is not None else 0.0,
        })

    for asset in (_get(incident, "affectedAssets", []) or []):
        asset_id = str(_get(asset, "id", _get(asset, "name", "")))
        if not asset_id:
            continue
        nodes.append({"id": asset_id, "type": "asset", "name": _get(asset, "name", asset_id)})
        relationships.append({
            "source": incident_id,
            "target": asset_id,
            "relationship_type": "impacts_asset",
            "valid_from": valid_from,
            "valid_to": None,
            "confidence": 0.0,
        })

    for event in (_get(incident, "timelineEvents", []) or []):
        technique_id = str(_get(event, "techniqueId", "")).strip()
        if technique_id:
            nodes.append({"id": technique_id, "type": "technique"})
            relationships.append({
                "source": incident_id,
                "target": technique_id,
                "relationship_type": "uses_technique",
                "valid_from": str(_get(event, "timestamp", valid_from)),
                "valid_to": None,
                "confidence": float(_get(event, "evidenceConfidence")) / 100.0 if _get(event, "evidenceConfidence") is not None else 0.0,
            })

    unique_nodes = []
    seen = set()
    for node in nodes:
        key = (node.get("id"), node.get("type"))
        if key in seen:
            continue
        seen.add(key)
        unique_nodes.append(node)

    return {
        "incident_id": incident_id,
        "nodes": unique_nodes,
        "relationships": relationships,
        "canonical": True,
        "generated_at": _now(),
    }
