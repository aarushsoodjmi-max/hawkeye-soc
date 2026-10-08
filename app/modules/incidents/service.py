from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from app.modules.assets.service import build_asset_dependencies
from app.modules.business_impact.service import assess_business_impact
from app.modules.confidence_engine.service import compute_confidence
from app.modules.decision_engine.service import generate_strategies
from app.modules.digital_twin.service import build_digital_twin_snapshot
from app.modules.incident_memory.service import memory_service
from app.modules.knowledge_graph.service import build_incident_knowledge_graph
from app.modules.prediction.service import predict_incident
from app.modules.risk_engine.service import score_incident_risk
from app.modules.threat_intelligence.service import build_threat_profile
from app.modules.workflow_intelligence.service import build_workflow_intelligence


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def hydrate_incident_intelligence(incident: Any, snapshot_reason: str = "state_change", workspace_id: str | None = None) -> Any:
    asset_dependencies = build_asset_dependencies(_get(incident, "affectedAssets", []) or [])
    incident.assetDependencies = asset_dependencies

    incident.knowledgeGraph = build_incident_knowledge_graph(incident)

    incident.threatIntelligence = build_threat_profile(incident)

    risk = score_incident_risk(incident)
    incident.riskScore = int(risk.get("risk_score", _get(incident, "riskScore", 0) or 0))
    incident.riskLevel = str(risk.get("risk_level", _get(incident, "riskLevel", "UNKNOWN"))).upper()
    incident.riskBreakdown = risk.get("breakdown", {})

    incident.businessImpact = assess_business_impact(incident)

    incident.workflowIntelligence = build_workflow_intelligence(incident)

    prediction = predict_incident(incident)
    incident.predictions = [p for p in (_get(incident, "predictions", []) or []) if p.get("status") == "ACTIVE"]
    incident.predictions.append(prediction)

    confidence = compute_confidence(incident)
    incident.confidenceAssessment = confidence
    incident.confidenceContract = {
        "version": "1.0",
        "subject_type": confidence.get("subject_type"),
        "subject_id": confidence.get("subject_id"),
        "unified_confidence": confidence.get("unified_confidence"),
        "computed_at": confidence.get("computed_at"),
    }

    strategies = [s.model_dump() if hasattr(s, "model_dump") else dict(s) for s in generate_strategies(incident)]
    for strategy in strategies:
        strategy["approval_required"] = True
        strategy["execution_state"] = "REQUIRES_APPROVAL"
    incident.decisionRecommendations = strategies
    incident.lastDecision = {"generated_at": _now(), "recommendations": strategies}
    existing_approval = _get(incident, "approvalState", {}) or {}
    if not (
        isinstance(existing_approval, dict)
        and existing_approval.get("required") is True
        and existing_approval.get("approved") is True
        and str(existing_approval.get("status", "")).upper() == "APPROVED"
    ):
        incident.approvalState = {
            "required": True,
            "approved": False,
            "status": "PENDING_APPROVAL",
            "updated_at": _now(),
        }

    if not workspace_id:
        raise ValueError("workspace_id is required to hydrate tenant-scoped incident memory")
    similar = memory_service.similar(incident, workspace_id=workspace_id, limit=5)
    incident.incidentMemory = {
        "workspace_id": workspace_id,
        "similar_incidents": similar,
        "record": memory_service.get_record(str(_get(incident, "id", _get(incident, "incident_id", ""))), workspace_id=workspace_id),
        "retrieval_mode": "structured",
    }

    snapshot = build_digital_twin_snapshot(incident, reason=snapshot_reason)
    incident.latestSimulation = incident.latestSimulation or {}
    existing = list(_get(incident, "digitalTwinSnapshots", []) or [])
    existing.append(snapshot)
    incident.digitalTwinSnapshots = existing[-10:]
    return incident
