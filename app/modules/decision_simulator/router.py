from fastapi import APIRouter, Depends, HTTPException, Query
from app.repositories import repository
from app.core.auth import Principal, require_roles
from app.modules.digital_twin.service import build_digital_twin_snapshot
from app.core.event_bus import event_bus
from app.core.audit import audit_log
from app.core.observability import set_request_context, reset_request_context, new_id
from .service import simulate

router = APIRouter()


@router.post('/incidents/{incident_id}/simulate')
def run(
    incident_id: str,
    max_depth: int = Query(5, ge=1, le=20),
    decay: float = Query(.7, gt=0, le=1),
    principal: Principal=Depends(require_roles("admin", "analyst")),
):
    incident = repository.get_incident_by_id(incident_id, workspace=principal.workspace)
    if not incident:
        raise HTTPException(404, 'Incident not found')
    decision = new_id()
    tokens = set_request_context(decision=decision, incident=incident_id, workspace=principal.workspace)
    try:
        body = simulate(incident, getattr(incident, 'assetDependencies', {}) or {}, max_depth, decay).model_dump()
    finally:
        reset_request_context(tokens)
    incident.latestSimulation = body
    existing = list(getattr(incident, "digitalTwinSnapshots", []) or [])
    existing.append(build_digital_twin_snapshot(incident, reason="decision_simulation"))
    incident.digitalTwinSnapshots = existing[-10:]
    if hasattr(repository, "_persist_incident"):
        repository._persist_incident(incident, principal.workspace)
    event_bus.publish_nowait('risk.updated', {
        'incident_id': incident_id,
        'source': 'decision_simulator',
        'confidence': body.get('confidence_score'),
        'workspace': principal.workspace,
    })
    audit_log.record("DECISION_SIMULATED", actor_id=principal.sub, role=principal.role, workspace_id=principal.workspace, outcome="SUCCESS", details={"decision_id": decision})
    return body
