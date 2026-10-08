"""
HawkEye SOC — Analysis Route
============================
Handles POST /analyze from frontend triage console.
Dispatches neural and heuristic analysis pipeline (tenant-scoped).
"""

from fastapi import APIRouter, Depends, HTTPException
from app.schemas import AnalyzeRequest, AnalyzeResponse
from app.repositories import repository
from app.core.auth import Principal, require_roles

router = APIRouter()


@router.post("", response_model=AnalyzeResponse)
@router.post("/", response_model=AnalyzeResponse)
def analyze_incident(payload: AnalyzeRequest, principal: Principal = Depends(require_roles("admin", "analyst"))):
    """
    POST /analyze
    Executes deep causal analysis on the specified incident using the ML predictor,
    explainability engine, and risk matrix (workspace-scoped).
    """
    success, analysis, updated_incident = repository.run_deep_analysis(
        incident_id=payload.incidentId,
        analyst_notes=payload.analystNotes,
        include_pcap=payload.includeTelemetryPcap or False,
        workspace=principal.workspace,
    )
    if not success or not analysis or not updated_incident:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{payload.incidentId}' could not be found for analysis.",
        )

    return AnalyzeResponse(
        success=True,
        analysis=analysis,
        updatedIncident=updated_incident,
    )
