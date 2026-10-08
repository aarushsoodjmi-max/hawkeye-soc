"""Deterministic incident prediction engine.

No LLM/embedding dependency: predictions are explainable heuristics derived from
incident telemetry, affected assets, techniques, and users.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

SEVERITY_DOWNTIME = {"CRITICAL": 8.0, "HIGH": 5.0, "MEDIUM": 2.5, "LOW": 1.0, "INFO": 0.5}
CRITICALITY_MULTIPLIER = {"TIER 0": 1.8, "TIER 1": 1.4, "TIER 2": 1.0, "TIER 3": 0.7}
LATERAL_TECHNIQUES = {"lateral movement", "remote services", "pass the ticket", "pass the hash", "smb/admin shares", "windows admin shares", "kerberoasting"}


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _asset_names(incident: Any) -> set[str]:
    return {str(_get(a, "name", "")).strip() for a in (_get(incident, "affectedAssets", []) or []) if _get(a, "name")}


def _prediction(incident: Any) -> Dict[str, Any]:
    assets = _get(incident, "affectedAssets", []) or []
    timeline = _get(incident, "timelineEvents", []) or []
    alerts = _get(incident, "alerts", []) or []
    severity = str(_get(incident, "severity", "HIGH")).upper()
    known_assets = _asset_names(incident)

    candidates: Dict[str, Dict[str, Any]] = {}
    for event in timeline:
        target = str(_get(event, "target", "")).strip()
        if target and target not in known_assets and target.upper() not in {"UNKNOWN", "N/A"}:
            candidates.setdefault(target, {"asset": target, "reason": "Observed as a downstream timeline target", "confidence": 0.58})
    for alert in alerts:
        host = str(_get(alert, "host", "")).strip()
        if host and host not in known_assets and host.upper() not in {"UNKNOWN-HOST", "UNKNOWN"}:
            candidates.setdefault(host, {"asset": host, "reason": "Repeated alert telemetry target", "confidence": 0.55})
    if not candidates and assets:
        ranked = sorted(assets, key=lambda a: CRITICALITY_MULTIPLIER.get(str(_get(a, "criticality", "TIER 2")).upper(), 1.0), reverse=True)
        for asset in ranked[:2]:
            name = str(_get(asset, "name", _get(asset, "id", "unknown")))
            candidates[name] = {"asset": name, "reason": "Highest-criticality asset remains exposed to the correlated attack path", "confidence": 0.48}

    techniques = [str(_get(e, "technique", "")).lower() for e in timeline]
    technique_text = " ".join(techniques)
    movement_hits = sum(1 for t in LATERAL_TECHNIQUES if t in technique_text)
    multi_asset = len({str(_get(a, "id", _get(a, "name", ""))) for a in assets}) > 1
    lateral_conf = min(0.99, 0.35 + 0.12 * movement_hits + (0.18 if multi_asset else 0.0) + (0.12 if severity in {"CRITICAL", "HIGH"} else 0.0))

    base = SEVERITY_DOWNTIME.get(severity, 2.0)
    criticality = max([CRITICALITY_MULTIPLIER.get(str(_get(a, "criticality", "TIER 2")).upper(), 1.0) for a in assets] or [1.0])
    downtime = round(min(72.0, base * criticality * max(1.0, 1 + 0.25 * max(0, len(assets) - 1))), 2)

    users = set()
    for alert in alerts:
        user = str(_get(alert, "user", "")).strip()
        if user and user.lower() not in {"system", "unknown", "none"}:
            users.add(user)
    root = _get(incident, "rootCause", None)
    compromised = str(_get(root, "compromisedAccount", "")).strip() if root else ""
    if compromised:
        users.add(compromised)
    affected_user_count = max(len(users), len(assets))
    user_conf = min(0.95, 0.42 + 0.08 * min(affected_user_count, 5) + (0.12 if compromised else 0))

    overall_confidence = round(sum([
        (max([c["confidence"] for c in candidates.values()] or [0.45])), lateral_conf, min(0.92, 0.55 + 0.06 * len(assets)), user_conf
    ]) / 4, 4)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    relevant_evidence = []
    for event in timeline[:5]:
        relevant_evidence.append({
            "type": "timeline_event",
            "title": str(_get(event, "title", _get(event, "technique", "event"))),
            "signal": str(_get(event, "techniqueId", _get(event, "technique", ""))),
            "confidence": round(float(_get(event, "evidenceConfidence", 0.0) or 0.0) / 100.0, 4),
        })
    for asset in list(candidates.values())[:3]:
        relevant_evidence.append({
            "type": "projected_asset",
            "title": asset["asset"],
            "signal": asset["reason"],
            "confidence": asset["confidence"],
        })

    return {
        "incident_id": str(_get(incident, "id", _get(incident, "incident_id", ""))),
        "prediction": "lateral_movement_and_service_impact" if (movement_hits or multi_asset) else "localized_containment_window",
        "confidence": overall_confidence,
        "relevant_evidence": relevant_evidence,
        "signals": {
            "movement_hits": movement_hits,
            "candidate_assets": len(candidates),
            "affected_user_count": affected_user_count,
        },
        "timestamp": timestamp,
        "status": "ACTIVE",
        "generated_at": timestamp,
        "next_affected_assets": list(candidates.values()),
        "lateral_movement": {"predicted": bool(movement_hits or multi_asset), "confidence": round(lateral_conf, 4), "signals": ["multiple affected assets"] if multi_asset else []},
        "downtime": {"estimated_hours": downtime, "confidence": round(min(0.92, 0.55 + 0.06 * len(assets)), 4), "basis": "severity × asset criticality × affected-asset count"},
        "affected_users": {"count": affected_user_count, "users": sorted(users), "confidence": round(user_conf, 4)},
        "overall_confidence": overall_confidence,
    }


def predict_incident(incident: Any) -> Dict[str, Any]:
    if incident is None:
        raise ValueError("incident is required")
    return _prediction(incident)
