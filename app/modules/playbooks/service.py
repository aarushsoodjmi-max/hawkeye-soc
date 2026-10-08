from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import List, Optional

from .schemas import ExecutionHistory, PlaybookAction
from app.db import PersistentStateRepository
from app.repositories import repository
from app.repositories.soc_repository import ActionApprovalError

ACTIONS = {"block_ip":"Block IP","disable_user":"Disable User","isolate_device":"Isolate Device","create_ticket":"Create Ticket","generate_report":"Generate Report"}
_store = PersistentStateRepository()


def _now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_action_payload(action: PlaybookAction) -> dict:
    return {"id": action.id, "action_type": action.action_type, "target": action.target, "description": action.description}


def _action_digest(actions: List[PlaybookAction]) -> str:
    raw = json.dumps([_canonical_action_payload(a) for a in actions], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _next_id(workspace_id: str):
    # UUID-style suffix avoids count-based collisions under concurrent requests.
    import uuid
    return f"PB-{uuid.uuid4().hex[:12].upper()}"


def create_playbook(incident_id: str, actions: List[str], target: str = "incident", actor: str = "simulator", workspace_id: str = "default") -> ExecutionHistory:
    if not workspace_id:
        raise ValueError("workspace_id is required")
    if repository.get_incident_by_id(incident_id, workspace=workspace_id) is None:
        raise ValueError("incident not found")
    now = _now()
    playbook_id = _next_id(workspace_id)
    suffix = playbook_id[3:]
    rows: List[PlaybookAction] = []
    for i, a in enumerate(actions, 1):
        key = a.lower().replace(" ", "_")
        label = ACTIONS.get(key, a)
        rows.append(PlaybookAction(
            id=f"PB-ACT-{suffix}-{i:02d}", action_type=label, target=target, status="SIMULATED",
            simulated_at=now, result="Simulated successfully (execution requires explicit approval)", description=label,
        ))
    h = ExecutionHistory(
        playbook_id=playbook_id, incident_id=incident_id, workspace_id=workspace_id,
        actions=rows, state="SIMULATED", simulation_id=f"SIM-{suffix}",
    )
    h.action_digest = _action_digest(rows)
    _store.upsert("playbooks", workspace_id, h.playbook_id, h.model_dump(mode="json"))
    return h


def approve_playbook(playbook_id: str, approver: str = "admin", incident_id: str | None = None, workspace_id: str = "default"):
    data = _store.get("playbooks", workspace_id, playbook_id)
    if not data or (incident_id is not None and data.get("incident_id") != incident_id):
        return None
    h = ExecutionHistory.model_validate(data)
    if h.state in {"EXECUTED", "VERIFICATION_FAILED", "FAILED"}:
        return h.model_dump(mode="json")
    if h.state != "SIMULATED":
        raise ActionApprovalError(f"playbook state {h.state!r} cannot be approved")
    now = _now()
    h.state = "APPROVED"
    h.approval = {"status": "APPROVED", "approved_by": approver, "approved_at": now, "action_digest": h.action_digest, "approved_actions": [{"id": a.id, "action_type": a.action_type, "target": a.target, "description": a.description} for a in h.actions]}
    incident = repository.get_incident_by_id(h.incident_id, workspace=workspace_id)
    if incident is not None:
        incident.approvalState = {
            "required": True, "approved": True, "status": "APPROVED",
            "playbook_id": h.playbook_id, "approved_by": approver,
            "approved_at": now, "action_digest": h.action_digest,
            "approved_actions": [_canonical_action_payload(a) for a in h.actions],
        }
        if hasattr(repository, "_persist_incident"):
            repository._persist_incident(incident, workspace_id)
    for action in h.actions:
        action.status = "PENDING"
        action.result = "Approved; awaiting explicit execution"
    result = h.model_dump(mode="json")
    _store.upsert("playbooks", workspace_id, h.playbook_id, result)
    return result



def reject_playbook(playbook_id: str, rejector: str = "admin", incident_id: str | None = None, workspace_id: str = "default"):
    data = _store.get("playbooks", workspace_id, playbook_id)
    if not data or (incident_id is not None and data.get("incident_id") != incident_id):
        return None
    h = ExecutionHistory.model_validate(data)
    if h.state in {"EXECUTED", "VERIFICATION_FAILED"}:
        raise ActionApprovalError("executed playbook cannot be rejected")
    now = _now()
    h.state = "REJECTED"
    h.approval = {"status": "REJECTED", "rejected_by": rejector, "rejected_at": now, "action_digest": h.action_digest}
    for action in h.actions:
        action.status = "REJECTED"
        action.result = "Rejected; execution prohibited"
    incident = repository.get_incident_by_id(h.incident_id, workspace=workspace_id)
    if incident is not None:
        incident.approvalState = {"required": True, "approved": False, "status": "REJECTED", "playbook_id": h.playbook_id, "rejected_by": rejector, "rejected_at": now}
        if hasattr(repository, "_persist_incident"):
            repository._persist_incident(incident, workspace_id)
    result = h.model_dump(mode="json")
    _store.upsert("playbooks", workspace_id, h.playbook_id, result)
    return result

def execute_playbook(playbook_id: str, executor: str, incident_id: str, workspace_id: str = "default"):
    data = _store.get("playbooks", workspace_id, playbook_id)
    if not data or data.get("incident_id") != incident_id:
        return None
    h = ExecutionHistory.model_validate(data)
    if h.state in {"EXECUTED", "VERIFICATION_FAILED", "FAILED"}:
        return h.model_dump(mode="json")
    if h.state != "APPROVED" or h.approval.get("status") != "APPROVED":
        raise ActionApprovalError("playbook is not approved")
    if h.approval.get("action_digest") != _action_digest(h.actions):
        raise ActionApprovalError("approved actions were modified after approval")

    incident = repository.get_incident_by_id(incident_id, workspace=workspace_id)
    if incident is None:
        return None
    # Bind playbook actions to canonical incident actions. This is the final
    # repository/service boundary, so alternate callers cannot bypass approval.
    from app.schemas import RecommendedAction
    for pb_action in h.actions:
        existing = next((a for a in incident.recommendedActions if a.id == pb_action.id), None)
        if existing is None:
            existing = RecommendedAction(
                id=pb_action.id, title=pb_action.action_type, description=pb_action.description or pb_action.action_type,
                type="CONTAINMENT", target=pb_action.target, riskLevel="HIGH", status="PENDING", playbookId=h.playbook_id,
            )
            incident.recommendedActions.append(existing)
        else:
            existing.title = pb_action.action_type
            existing.description = pb_action.description or existing.description
            existing.target = pb_action.target
            existing.playbookId = h.playbook_id

    # Execution is deliberately delegated to the canonical repository gate.
    try:
        for pb_action in h.actions:
            action = repository.execute_action(incident_id, pb_action.id, workspace=workspace_id)
            if action is None:
                raise ActionApprovalError("execution target not found")
            pb_action.status = action.status
            pb_action.executed_at = action.executedAt
            pb_action.executed_by = executor
            pb_action.result = "Executed; verification pending"
    except Exception as exc:
        for pb_action in h.actions:
            if pb_action.status not in {"COMPLETED", "FAILED"}:
                pb_action.status = "FAILED"
                pb_action.result = "Execution failed"
        h.state = "FAILED"
        import uuid
        h.execution = {"execution_id": f"EXEC-{uuid.uuid4().hex[:12].upper()}", "status": "FAILED", "executed_by": executor, "executed_at": _now(), "reason": "execution failed"}
        result = h.model_dump(mode="json")
        _store.upsert("playbooks", workspace_id, h.playbook_id, result)
        _store.upsert("playbook_executions", workspace_id, h.playbook_id, result)
        return result

    verified, verification = verify_playbook(h, incident_id, workspace_id)
    import uuid
    execution_id = h.execution.get("execution_id") or f"EXEC-{uuid.uuid4().hex[:12].upper()}"
    h.execution = {"execution_id": execution_id, "status": "VERIFIED" if verified else "VERIFICATION_FAILED", "executed_by": executor, "executed_at": _now(), "verification": verification}
    h.state = "EXECUTED" if verified else "VERIFICATION_FAILED"
    if not verified:
        for action in h.actions:
            action.result = "Execution completed but containment verification failed"
    result = h.model_dump(mode="json")
    _store.upsert("playbooks", workspace_id, h.playbook_id, result)
    _store.upsert("playbook_executions", workspace_id, h.playbook_id, result)
    return result


def verify_playbook(playbook: ExecutionHistory, incident_id: str, workspace_id: str):
    incident = repository.get_incident_by_id(incident_id, workspace=workspace_id)
    if incident is None:
        return False, {"status": "FAILED", "reason": "incident not found"}
    checks = []
    verification = (incident.metadata or {}).get("playbookVerification", {})
    signals = verification.get("signals", {}) if isinstance(verification, dict) else {}
    for action in playbook.actions:
        title = action.action_type.lower()
        if title in {"isolate device", "quarantine device"}:
            target = action.target.lower()
            matched = [a for a in incident.affectedAssets if target in str(a.name).lower() or target in str(a.ip).lower() or target in str(a.id).lower()]
            ok = bool(matched) and all(str(a.status).upper() == "ISOLATED" for a in matched)
            checks.append({"action_id": action.id, "type": "asset_isolation", "verified": ok})
        else:
            signal = signals.get(action.id, {}) if isinstance(signals, dict) else {}
            checks.append({"action_id": action.id, "type": signal.get("type", title.replace(" ", "_")), "verified": signal.get("verified") is True, "signal": signal})
    ok = bool(checks) and all(c["verified"] for c in checks)
    return ok, {"status": "VERIFIED" if ok else "FAILED", "checks": checks}


def history(incident_id: str | None = None, workspace_id: str = "default"):
    return [ExecutionHistory.model_validate(x) for x in _store.list("playbooks", workspace_id, 100000) if incident_id is None or x.get("incident_id") == incident_id]
