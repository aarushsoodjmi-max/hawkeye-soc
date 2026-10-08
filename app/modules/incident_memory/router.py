from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.repositories import repository
from app.core.auth import Principal, current_principal, require_roles
from .service import memory_service

router = APIRouter(dependencies=[Depends(current_principal)])


class NoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=10000)
    author_id: str = Field("analyst", min_length=1, max_length=256)


def _incident(i: str, workspace: str):
    x = repository.get_incident_by_id(i, workspace=workspace)
    if not x:
        raise HTTPException(status_code=404, detail=f"Incident {i} not found")
    return x


@router.get("/incidents/{incident_id}/similar")
def similar(incident_id: str, limit: int = 10, principal: Principal = Depends(current_principal)):
    return {
        "incident_id": incident_id,
        "similar_incidents": memory_service.similar(_incident(incident_id, principal.workspace), workspace_id=principal.workspace, limit=limit),
    }


@router.post("/incidents/{incident_id}/notes")
def add_note(incident_id: str, payload: NoteRequest, principal: Principal = Depends(require_roles("admin", "analyst"))):
    _incident(incident_id, principal.workspace)
    return memory_service.add_note(incident_id, payload.note, workspace_id=principal.workspace, author_id=principal.sub)


@router.get("/incidents/{incident_id}/notes")
def notes(incident_id: str, principal: Principal = Depends(current_principal)):
    _incident(incident_id, principal.workspace)
    return {"incident_id": incident_id, "notes": memory_service.get_notes(incident_id, workspace_id=principal.workspace)}


@router.get("/patterns")
def patterns(principal: Principal = Depends(current_principal)):
    allowed = {i.id for i in repository.get_incidents(workspace=principal.workspace)[0]}
    filtered = []
    for p in memory_service.get_patterns(workspace_id=principal.workspace):
        related = [rid for rid in p.get("related_incident_ids", []) if rid in allowed]
        if related:
            filtered.append({**p, "related_incident_ids": related})
    return {"patterns": filtered}


@router.get("/records/{incident_id}")
def record(incident_id: str, principal: Principal = Depends(current_principal)):
    _incident(incident_id, principal.workspace)
    x = memory_service.get_record(incident_id, workspace_id=principal.workspace)
    if not x:
        raise HTTPException(status_code=404, detail=f"No memory record for incident {incident_id}")
    return x
