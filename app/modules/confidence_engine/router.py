from fastapi import APIRouter, Depends, HTTPException
from app.repositories import repository
from app.core.auth import Principal, current_principal
from .service import compute_confidence

router = APIRouter(dependencies=[Depends(current_principal)])


@router.get("/{subject_type}/{subject_id}")
def confidence(subject_type: str, subject_id: str, principal: Principal = Depends(current_principal)):
    if subject_type != "incident":
        raise HTTPException(status_code=400, detail="Session 5 currently supports subject_type=incident")
    incident = repository.get_incident_by_id(subject_id, workspace=principal.workspace)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {subject_id} not found")
    # GET is strictly read-only. Compute from the current canonical incident
    # object without mutating/persisting it and without publishing an event.
    return compute_confidence(incident)
