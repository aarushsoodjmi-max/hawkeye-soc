from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.core.auth import Principal, current_principal, require_roles
from app.services.transport_service import _dashboard, _events, _incidents, _assets, _graph, _reports
from app.repositories import repository
from app.schemas import DashboardMetrics, IncidentsResponse, StatusUpdateRequest
from app.db.repositories import list_audit_logs
from app.core.event_bus import event_bus
from app.core.audit import audit_log
from app.core.observability import set_request_context, reset_request_context, new_id
from app.modules.decision_simulator.service import simulate
from app.modules.digital_twin.service import build_digital_twin_snapshot

router = APIRouter(prefix="/api", dependencies=[Depends(current_principal)])


@router.get("/dashboard", response_model=DashboardMetrics)
def dashboard(principal: Principal = Depends(current_principal)):
    return _dashboard.get(principal.workspace)


@router.get("/events")
def events(limit: int = Query(100, ge=1, le=1000), principal: Principal = Depends(current_principal)):
    return _events.list(limit, principal.workspace)


@router.get("/incidents", response_model=IncidentsResponse)
def incidents(principal: Principal = Depends(current_principal)):
    from datetime import datetime, timezone
    incidents_list, kpis = repository.get_incidents(workspace=principal.workspace)
    return IncidentsResponse(
        incidents=incidents_list,
        kpis=kpis,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


@router.get("/incidents/{incident_id}")
def incident(incident_id: str, principal: Principal = Depends(current_principal)):
    x = _incidents.get(incident_id, principal.workspace)
    if not x:
        raise HTTPException(404, "Incident not found")
    return x


@router.get("/assets")
def assets(principal: Principal = Depends(current_principal)):
    return _assets.list(principal.workspace)


@router.get("/assets/{asset_id}")
def asset(asset_id: str, principal: Principal = Depends(current_principal)):
    x = _assets.get(asset_id, principal.workspace)
    if not x:
        raise HTTPException(404, "Asset not found")
    return x


@router.get("/graph")
def graph(principal: Principal = Depends(current_principal)):
    return _graph.graph(principal.workspace)


@router.get("/graph/traverse")
def traverse(entity_id: str, depth: int = Query(2, ge=1, le=20), principal: Principal = Depends(current_principal)):
    return _graph.traverse(entity_id, depth, principal.workspace)


@router.get("/alerts")
def alerts(
    severity: str | None = None,
    status: str | None = None,
    search: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(current_principal),
):
    """Canonical alerts list (workspace-scoped)."""
    from datetime import datetime, timezone
    alerts_list, total = repository.get_alerts(
        severity=severity, status=status, search=search, limit=limit, offset=offset, workspace=principal.workspace
    )
    return {"alerts": alerts_list, "total": total, "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}


@router.get("/alerts/{alert_id}")
def alert_by_id(alert_id: str, principal: Principal = Depends(current_principal)):
    """Canonical alert detail (workspace-scoped)."""
    alert = repository.get_alert_by_id(alert_id, workspace=principal.workspace)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.post("/alerts")
def ingest_alert_canonical(payload: dict, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Ingest a real alert through the canonical /api contract."""
    try:
        ingested, incident_id = repository.ingest_alerts([payload], workspace=principal.workspace)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return {
        "success": True,
        "message": "Alert ingested successfully",
        "alert": ingested[0] if ingested else None,
        "correlatedIncidentId": incident_id,
        "incidentId": incident_id,
    }


@router.put("/incidents/{incident_id}/status")
def update_status_canonical(incident_id: str, payload: StatusUpdateRequest, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Canonical incident status update (workspace-scoped)."""
    updated = repository.update_incident_status(incident_id, payload.status, workspace=principal.workspace)
    if updated is None:
        raise HTTPException(404, "Incident not found")
    audit_log.record("INCIDENT_STATUS_CHANGED", actor_id=principal.sub, role=principal.role, workspace_id=principal.workspace, outcome="SUCCESS", details={"to": payload.status})
    return {"message": "Incident status updated", "incident": updated}


@router.post("/incidents/{incident_id}/actions/{action_id}/execute")
def execute_canonical(incident_id: str, action_id: str, principal: Principal = Depends(require_roles("admin", "operator"))):
    """Canonical SOAR execution — repository approval gate remains authoritative."""
    from app.repositories.soc_repository import ActionApprovalError
    try:
        action = repository.execute_action(incident_id, action_id, workspace=principal.workspace)
    except ActionApprovalError as exc:
        raise HTTPException(status_code=409, detail=exc.reason) from exc
    if action is None:
        raise HTTPException(404, "Action not found")
    return {"success": True, "message": f"Action {action.title} executed successfully", "action": action}


@router.post("/incidents/{incident_id}/assets/{asset_id}/toggle-isolation")
def toggle_isolation_canonical(incident_id: str, asset_id: str, principal: Principal = Depends(require_roles("admin", "operator"))):
    """Canonical asset isolation toggle — approval gate remains authoritative."""
    from app.repositories.soc_repository import ActionApprovalError
    try:
        incident = repository.toggle_asset_isolation(incident_id, asset_id, workspace=principal.workspace)
    except ActionApprovalError as exc:
        raise HTTPException(status_code=409, detail=exc.reason) from exc
    if not incident:
        raise HTTPException(404, "Asset or incident not found")
    return {"success": True, "message": "Asset isolation status toggled", "incident": incident}


@router.post("/incidents/{incident_id}/simulate")
def simulate_alias(incident_id: str, principal: Principal = Depends(require_roles("admin", "analyst"))):
    x = _incidents.get(incident_id, principal.workspace)
    if not x:
        raise HTTPException(404, "Incident not found")
    decision = new_id()
    tokens = set_request_context(decision=decision, incident=incident_id, workspace=principal.workspace)
    try:
        result = simulate(x, getattr(x, "assetDependencies", {}) or {}).model_dump()
    finally:
        reset_request_context(tokens)
    audit_log.record("DECISION_SIMULATED", actor_id=principal.sub, role=principal.role, workspace_id=principal.workspace, outcome="SUCCESS", details={"decision_id": decision})
    x.latestSimulation = result
    existing = list(getattr(x, "digitalTwinSnapshots", []) or [])
    existing.append(build_digital_twin_snapshot(x, reason="decision_simulation"))
    x.digitalTwinSnapshots = existing[-10:]
    event_bus.publish_nowait("risk.updated", {
        "incident_id": incident_id,
        "source": "decision_simulator",
        "confidence": result.get("confidence_score"),
        "workspace": principal.workspace,
    })
    return result


@router.get("/audit")
def audit(limit: int = Query(100, ge=1, le=1000), principal: Principal = Depends(current_principal)):
    return {"records": list_audit_logs(principal.workspace, limit=limit)}

@router.get("/reports")
def reports(principal: Principal = Depends(current_principal)):
    return _reports.list(principal.workspace)


@router.get("/reports/{incident_id}")
def report(incident_id: str, principal: Principal = Depends(current_principal)):
    result = _reports.generate(incident_id, principal.workspace)
    if not result:
        raise HTTPException(404, "Incident report not found")
    return result


@router.get("/reports/{incident_id}/executive")
def executive_report(incident_id: str, principal: Principal = Depends(current_principal)):
    result = _reports.executive(incident_id, principal.workspace)
    if not result:
        raise HTTPException(404, "Incident report not found")
    return result


@router.post("/reports/{incident_id}/export")
def export_report(incident_id: str, principal: Principal = Depends(current_principal)):
    path = _reports.export(incident_id, principal.workspace)
    if not path:
        raise HTTPException(404, "Incident report not found")
    return {"success": True, "incident_id": incident_id, "path": path}


class CreateIncidentRequest(BaseModel):
    title: str | None = None
    alerts: list[dict] = []


@router.post("/incidents")
def create_incident_canonical(payload: CreateIncidentRequest, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Create a new incident (manual creation or from a provided alert batch)."""
    from datetime import datetime, timezone
    alerts = payload.alerts
    if not alerts:
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        alerts = [{
            "alert_id": f"ALT-{new_id()[-8:]}", "timestamp": now, "title": payload.title or "Manually Created Incident",
            "event_type": payload.title or "Manually Created Incident", "severity": "HIGH", "user": "analyst",
            "device": "HOST-01", "ip_address": "10.0.0.1", "destination_ip": "10.0.0.2", "source": "Manual",
            "mitre_technique": "T1059", "description": payload.title or "Incident created by an operator.",
        }]
    ingested, incident_id = repository.ingest_alerts(alerts, workspace=principal.workspace)
    incident = repository.get_incident_by_id(incident_id, workspace=principal.workspace) if incident_id else None
    if incident is None:
        raise HTTPException(400, "Could not create an incident from the provided payload")
    return {"success": True, "message": "Incident created", "incidentId": incident.id, "incident": incident}


class ContainmentDirectives(BaseModel):
    directives: dict[str, bool] = {}


@router.post("/incidents/{incident_id}/contain")
def contain_incident_canonical(incident_id: str, payload: ContainmentDirectives, principal: Principal = Depends(require_roles("admin", "operator"))):
    """Execute operator containment directives: status, assets, timeline, persistence."""
    incident = repository.contain_incident(
        incident_id, workspace=principal.workspace, directives=payload.directives,
        actor=principal.sub, role=principal.role,
    )
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return {"success": True, "message": "Containment directives executed", "incident": incident}


class BlockIpRequest(BaseModel):
    ip: str


@router.post("/containment/block-ip")
def block_ip_canonical(payload: BlockIpRequest, principal: Principal = Depends(require_roles("admin", "operator"))):
    """Block an adversary IP: mark matching alerts CONTAINED and record timeline events."""
    incidents = repository.block_ip(payload.ip, workspace=principal.workspace, actor=principal.sub)
    return {
        "success": True, "message": f"Blocked adversary IP {payload.ip}", "blocked": True,
        "incidents": incidents, "affectedIncidentIds": [i.id for i in incidents],
    }


class QuarantineRequest(BaseModel):
    host: str


@router.post("/containment/quarantine-host")
def quarantine_host_canonical(payload: QuarantineRequest, principal: Principal = Depends(require_roles("admin", "operator"))):
    """Isolate a host across the workspace's incidents."""
    incident = repository.quarantine_host(payload.host, workspace=principal.workspace, actor=principal.sub)
    if incident is None:
        raise HTTPException(404, "Host not found in any incident")
    return {"success": True, "message": f"Host {payload.host} isolated", "incident": incident}


class CorrelateRequest(BaseModel):
    alert_id: str


@router.post("/containment/correlate")
def correlate_alert_canonical(payload: CorrelateRequest, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Correlate an unlinked alert into an incident (creating one if needed)."""
    incident = repository.correlate_alert_to_incident(payload.alert_id, workspace=principal.workspace)
    if incident is None:
        raise HTTPException(404, "Alert not found")
    return {
        "success": True, "message": f"Alert {payload.alert_id} correlated to {incident.id}",
        "incidentId": incident.id, "incident": incident,
    }


@router.post("/events/clear")
def clear_events_canonical(principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Reset the telemetry buffer: drop alerts not linked to any incident."""
    removed = repository.clear_workspace_events(principal.workspace)
    return {"success": True, "removed": removed, "message": f"Removed {removed} unlinked event(s) from the telemetry buffer"}


@router.put("/alerts/{alert_id}/status")
def update_alert_status_canonical(alert_id: str, payload: StatusUpdateRequest, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Update alert lifecycle status (workspace-scoped)."""
    updated = repository.update_alert_status(alert_id, payload.status, principal.workspace)
    if not updated:
        raise HTTPException(404, "Alert not found")
    return {"message": "Status updated", "alert": updated}
