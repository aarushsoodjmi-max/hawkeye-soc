from fastapi import APIRouter, Depends, HTTPException, Query
from app.repositories import repository
from app.core.auth import Principal, current_principal
from .service import predict_incident

router = APIRouter(dependencies=[Depends(current_principal)])


def _incident(i: str, workspace: str):
    x = repository.get_incident_by_id(i, workspace=workspace)
    if not x:
        raise HTTPException(status_code=404, detail=f"Incident {i} not found")
    return x


@router.get("/incidents/{incident_id}")
def predict(incident_id: str, principal: Principal = Depends(current_principal)):
    incident = _incident(incident_id, principal.workspace)
    result = predict_incident(incident)
    incident.predictions = [p for p in (incident.predictions or []) if p.get("status") == "ACTIVE"]
    incident.predictions.append(result)
    if hasattr(repository, "_persist_incident"):
        repository._persist_incident(incident, principal.workspace)
    return result
