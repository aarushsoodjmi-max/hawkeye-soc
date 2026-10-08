from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.repositories import repository
from app.core.auth import Principal, current_principal, require_roles
from .service import approve_playbook, create_playbook, execute_playbook, reject_playbook, history
from app.core.event_bus import event_bus
from app.core.audit import audit_log
from app.core.observability import set_request_context, reset_request_context

router = APIRouter()


class ExecuteRequest(BaseModel):
    actions: list[str] = Field(default_factory=list)
    target: str = Field('incident', min_length=1, max_length=256)
    playbook_id: str | None = Field(None, min_length=1, max_length=128)


def _incident(incident_id: str, workspace: str):
    incident = repository.get_incident_by_id(incident_id, workspace=workspace)
    if incident is None:
        raise HTTPException(404, "Incident not found")
    return incident


@router.post('/incidents/{incident_id}/playbooks/simulate')
def simulate(incident_id: str, body: ExecuteRequest, principal: Principal=Depends(require_roles("admin", "analyst", "operator"))):
    """Create a playbook in SIMULATED state. Execution stays behind explicit approval."""
    _incident(incident_id, principal.workspace)
    if not body.actions:
        raise HTTPException(400, 'At least one action is required')
    result = create_playbook(incident_id, body.actions, body.target, principal.sub, workspace_id=principal.workspace).model_dump()
    incident = _incident(incident_id, principal.workspace)
    incident.approvalState = {
        "required": True,
        "approved": False,
        "status": "PENDING_APPROVAL",
        "playbook_id": result.get("playbook_id"),
        "updated_at": result.get("actions", [{}])[0].get("executed_at"),
    }
    try:
        audit_log.record("PLAYBOOK_SIMULATED", actor_id=principal.sub, role=principal.role, workspace_id=principal.workspace, outcome="SUCCESS", details={"playbook_id": result.get("playbook_id")})
    except Exception as exc:
        import logging
        logging.getLogger("hawkeye.playbooks").error("Playbook simulation audit failed: %s", type(exc).__name__)
    event_bus.publish_nowait('playbook.executed', {**result, "execution_state": "SIMULATED", "workspace": principal.workspace})
    return result


@router.post('/incidents/{incident_id}/playbooks/{playbook_id}/approve')
def approve(incident_id: str, playbook_id: str, principal: Principal=Depends(require_roles("admin", "analyst", "operator"))):
    """Explicit human approval gate. Approval never executes the playbook."""
    _incident(incident_id, principal.workspace)
    result = approve_playbook(playbook_id, approver=principal.sub, incident_id=incident_id, workspace_id=principal.workspace)
    if result:
        tokens = set_request_context(incident=incident_id, workspace=principal.workspace)
        try: audit_log.record("PLAYBOOK_APPROVED", actor_id=principal.sub, role=principal.role, workspace_id=principal.workspace, outcome="SUCCESS", details={"playbook_id": playbook_id})
        finally: reset_request_context(tokens)
    if not result:
        raise HTTPException(404, 'Playbook not found')
    incident = _incident(incident_id, principal.workspace)
    incident.approvalState = {
        "required": True, "approved": True, "status": "APPROVED",
        "playbook_id": playbook_id, "approved_by": principal.sub,
        "updated_at": result.get("approval", {}).get("approved_at"),
        "action_digest": result.get("action_digest"),
    }
    repository.update_incident_status(incident_id, "PENDING_APPROVAL", workspace=principal.workspace) if incident.status == "PENDING_APPROVAL" else None
    event_bus.publish_nowait('playbook.executed', {**result, "execution_state": "APPROVED", "workspace": principal.workspace})
    return result


@router.post('/incidents/{incident_id}/playbooks/{playbook_id}/reject')
def reject(incident_id: str, playbook_id: str, principal: Principal=Depends(require_roles("admin", "analyst", "operator"))):
    """Reject a simulated playbook; rejected actions can never execute."""
    _incident(incident_id, principal.workspace)
    result = reject_playbook(playbook_id, rejector=principal.sub, incident_id=incident_id, workspace_id=principal.workspace)
    if result: audit_log.record("PLAYBOOK_REJECTED", actor_id=principal.sub, role=principal.role, workspace_id=principal.workspace, outcome="SUCCESS", details={"playbook_id": playbook_id})
    if not result:
        raise HTTPException(404, 'Playbook not found')
    event_bus.publish_nowait('playbook.executed', {**result, "execution_state": "REJECTED", "workspace": principal.workspace})
    return result


@router.post('/incidents/{incident_id}/playbooks/execute')
def execute(incident_id: str, body: ExecuteRequest, principal: Principal=Depends(require_roles("admin", "analyst", "operator"))):
    """Execute only an explicitly approved playbook, then verify postconditions."""
    _incident(incident_id, principal.workspace)
    playbook_id = getattr(body, "playbook_id", None)
    if not playbook_id:
        raise HTTPException(409, "playbook_id is required; simulate and approve before execution")
    try:
        result = execute_playbook(playbook_id, executor=principal.sub, incident_id=incident_id, workspace_id=principal.workspace)
        if result: audit_log.record("PLAYBOOK_EXECUTION", actor_id=principal.sub, role=principal.role, workspace_id=principal.workspace, outcome=result.get("state", "COMPLETED"), details={"playbook_id": playbook_id, "execution_id": result.get("execution_id")})
    except Exception as exc:
        from app.repositories.soc_repository import ActionApprovalError
        if isinstance(exc, ActionApprovalError):
            raise HTTPException(409, detail=exc.reason) from exc
        raise
    if not result:
        raise HTTPException(404, 'Playbook not found')
    event_bus.publish_nowait('playbook.executed', {**result, "workspace": principal.workspace})
    return result


@router.get('/incidents/{incident_id}/playbooks/history')
def get_history(incident_id: str, principal: Principal = Depends(current_principal)):
    _incident(incident_id, principal.workspace)
    return [x.model_dump() for x in history(incident_id, workspace_id=principal.workspace)]
