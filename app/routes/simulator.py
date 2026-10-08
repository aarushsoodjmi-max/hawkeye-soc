"""
HawkEye SOC — Attack Simulator Route
====================================
Triggers synthetic cyber attack scenarios, generating real telemetry alerts
and driving them through the full ingestion, correlation, and ML pipeline.
"""

from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.schemas import SimulateRequest
from app.simulator.attack_simulator import AttackSimulator
from app.repositories import repository
from app.core.auth import Principal, require_roles

router = APIRouter()


@router.get("/scenarios")
def list_available_scenarios():
    """List all available attack scenarios supported by the simulator."""
    sim = AttackSimulator()
    return {"scenarios": sim.available_scenarios()}


@router.post("")
@router.post("/")
def run_simulation(payload: SimulateRequest, principal: Principal = Depends(require_roles("admin", "analyst", "operator"))):
    """
    POST /simulate
    Generates synthetic attack telemetry for the requested scenario,
    ingests the alerts, runs correlation & ML root-cause analysis,
    and returns the resulting incident and alerts (bound to the caller's workspace).
    """
    alerts, incident = repository.run_simulation(
        scenario_name=payload.scenario,
        seed=payload.seed,
        workspace=principal.workspace,
    )
    return {
        "success": True,
        "scenario": payload.scenario,
        "alertsCount": len(alerts),
        "incidentId": incident.id if incident else None,
        "incident": incident,
        "alerts": alerts,
    }
