from __future__ import annotations
from contextvars import ContextVar

request_id_var: ContextVar[str | None] = ContextVar('request_id', default=None)
workspace_id_var: ContextVar[str | None] = ContextVar('workspace_id', default=None)
incident_id_var: ContextVar[str | None] = ContextVar('incident_id', default=None)
event_id_var: ContextVar[str | None] = ContextVar('event_id', default=None)
ai_request_id_var: ContextVar[str | None] = ContextVar('ai_request_id', default=None)
decision_id_var: ContextVar[str | None] = ContextVar('decision_id', default=None)
execution_id_var: ContextVar[str | None] = ContextVar('execution_id', default=None)

def ids() -> dict[str, str | None]:
    return {k: v.get() for k, v in {
        'request_id': request_id_var, 'workspace_id': workspace_id_var,
        'incident_id': incident_id_var, 'event_id': event_id_var,
        'ai_request_id': ai_request_id_var, 'decision_id': decision_id_var,
        'execution_id': execution_id_var,
    }.items()}
