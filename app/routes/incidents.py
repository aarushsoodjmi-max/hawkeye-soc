"""
HawkEye SOC — Incidents Routes
==============================
Provides real incident management, triage, SOAR execution, and asset isolation.
All data access is tenant-scoped to the authenticated principal's workspace.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel

from app.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    Incident,
    IncidentsResponse,
    RecommendedAction,
    StatusUpdateRequest,
)
from app.repositories import repository
from app.repositories.soc_repository import ActionApprovalError
from app.core.auth import Principal, require_roles
from app.core.audit import audit_log
from app.core.observability import set_request_context, reset_request_context
from app.modules.incident_memory.service import memory_service

router = APIRouter()


@router.get("", response_model=IncidentsResponse)
@router.get("/", response_model=IncidentsResponse)
def list_incidents(principal: Principal = Depends(require_roles("viewer", "analyst", "operator", "admin"))):
    """Return all incidents visible to the caller's workspace along with KPIs."""
    incidents, kpis = repository.get_incidents(workspace=principal.workspace)
    from datetime import datetime, timezone
    return IncidentsResponse(
        incidents=incidents,
        kpis=kpis,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


@router.get("/{incident_id}", response_model=Incident)
def get_incident(incident_id: str, principal: Principal = Depends(require_roles("viewer", "analyst", "operator", "admin"))):
    """Retrieve full details of a correlated incident (workspace-scoped)."""
    incident = repository.get_incident_by_id(incident_id, workspace=principal.workspace)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


@router.put("/{incident_id}/status")
def update_incident_status(incident_id: str, payload: StatusUpdateRequest, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Update incident status (ACTIVE, TRIAGING, CONTAINED, MITIGATED, CLOSED)."""
    previous = repository.get_incident_by_id(incident_id, workspace=principal.workspace)
    previous_status = previous.status if previous else None
    updated = repository.update_incident_status(incident_id, payload.status, workspace=principal.workspace)
    if updated is not None:
        tokens = set_request_context(incident=incident_id, workspace=principal.workspace)
        try:
            audit_log.record("INCIDENT_STATUS_CHANGED", actor_id=principal.sub, role=principal.role, workspace_id=principal.workspace, outcome="SUCCESS", details={"from": getattr(previous, "status", None), "to": payload.status})
        finally:
            reset_request_context(tokens)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    if payload.status == "CLOSED" and previous_status != "CLOSED":
        memory_service.record_closed(updated, workspace_id=principal.workspace)
    return {"message": "Incident status updated", "incident": updated}


@router.post("/{incident_id}/actions/{action_id}/execute")
def execute_recommended_action(
    incident_id: str = Path(..., description="Target incident ID"),
    action_id: str = Path(..., description="Action ID to execute"),
    principal: Principal = Depends(require_roles("admin", "operator")),
):
    """
    Execute a SOAR containment/remediation playbook action.
    Updates asset isolation status if host quarantine action.
    """
    try:
        action = repository.execute_action(incident_id, action_id, workspace=principal.workspace)
    except ActionApprovalError as exc:
        raise HTTPException(status_code=409, detail=exc.reason) from exc
    if not action:
        raise HTTPException(
            status_code=404,
            detail=f"Action {action_id} not found for incident {incident_id}",
        )
    return {
        "success": True,
        "message": f"Action {action.title} executed successfully",
        "action": action,
    }


@router.post("/{incident_id}/assets/{asset_id}/toggle-isolation")
def toggle_asset_isolation(
    incident_id: str = Path(..., description="Incident ID"),
    asset_id: str = Path(..., description="Asset ID to toggle"),
    principal: Principal = Depends(require_roles("admin", "operator")),
):
    """Toggle asset status between COMPROMISED and ISOLATED."""
    try:
        incident = repository.toggle_asset_isolation(incident_id, asset_id, workspace=principal.workspace)
    except ActionApprovalError as exc:
        raise HTTPException(status_code=409, detail=exc.reason) from exc
    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Asset {asset_id} or incident {incident_id} not found",
        )
    return {
        "success": True,
        "message": "Asset isolation status toggled",
        "incident": incident,
    }


@router.post("/{incident_id}/analyze", response_model=AnalyzeResponse)
def analyze_incident_scoped(incident_id: str, payload: Optional[AnalyzeRequest] = None, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Execute deep ML/AI analysis on a specific incident (workspace-scoped)."""
    notes = payload.analystNotes if payload else None
    include_pcap = payload.includeTelemetryPcap if payload else False
    success, analysis, updated_incident = repository.run_deep_analysis(
        incident_id, analyst_notes=notes, include_pcap=include_pcap, workspace=principal.workspace
    )
    if not success or not analysis or not updated_incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return AnalyzeResponse(
        success=True,
        analysis=analysis,
        updatedIncident=updated_incident,
    )
