"""
HawkEye SOC — Alerts Routes
===========================
Provides real alert telemetry ingestion, querying, and triage.
All data access is tenant-scoped to the authenticated principal's workspace.
"""

from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.schemas import Alert, AlertsResponse, StatusUpdateRequest
from app.repositories import repository
from app.core.auth import Principal, require_roles

router = APIRouter()


@router.get("", response_model=AlertsResponse)
@router.get("/", response_model=AlertsResponse)
def list_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    status: Optional[str] = Query(None, description="Filter by status (NEW, INVESTIGATING, CONTAINED, RESOLVED)"),
    incidentId: Optional[str] = Query(None, description="Filter by linked incident ID"),
    search: Optional[str] = Query(None, description="Search term in title, host, IP, user"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(require_roles("viewer", "analyst", "operator", "admin")),
):
    """Query live SIEM and EDR alerts visible to the caller's workspace."""
    alerts, total = repository.get_alerts(
        severity=severity,
        status=status,
        incident_id=incidentId,
        search=search,
        limit=limit,
        offset=offset,
        workspace=principal.workspace,
    )
    from datetime import datetime, timezone
    return AlertsResponse(
        alerts=alerts,
        total=total,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


@router.get("/{alert_id}", response_model=Alert)
def get_alert(alert_id: str, principal: Principal = Depends(require_roles("viewer", "analyst", "operator", "admin"))):
    """Retrieve details of a specific alert (workspace-scoped)."""
    alert = repository.get_alert_by_id(alert_id, workspace=principal.workspace)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


@router.post("")
@router.post("/")
def ingest_alert(alert_data: Dict[str, Any], principal: Principal = Depends(require_roles("admin", "analyst"))):
    """
    Ingest a single alert into the SOC pipeline (bound to the caller's workspace).
    Triggers normalization, correlation, ML inference, and risk scoring.
    """
    try:
        ingested, incident_id = repository.ingest_alerts([alert_data], workspace=principal.workspace)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return {
        "success": True,
        "message": "Alert ingested successfully",
        "alert": ingested[0] if ingested else None,
        "correlatedIncidentId": incident_id,
        "incidentId": incident_id,
    }


@router.post("/batch")
def ingest_alerts_batch(alerts_data: List[Dict[str, Any]], principal: Principal = Depends(require_roles("admin", "analyst"))):
    """
    Ingest a batch of telemetry alerts into the SOC pipeline (caller's workspace).
    Triggers correlation clustering, ML inference, and incident generation.
    """
    try:
        ingested, incident_id = repository.ingest_alerts(alerts_data, workspace=principal.workspace)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    return {
        "success": True,
        "message": f"Successfully ingested {len(ingested)} alerts",
        "count": len(ingested),
        "correlatedIncidentId": incident_id,
        "incidentId": incident_id,
    }


@router.put("/{alert_id}/status")
@router.put("/{alert_id}")
def update_alert_status(alert_id: str, payload: StatusUpdateRequest, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """Update lifecycle status of an alert (workspace-scoped)."""
    updated = repository.update_alert_status(alert_id, payload.status, workspace=principal.workspace)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return {"message": "Status updated", "alert": updated}
