from __future__ import annotations

import contextvars
import re
import uuid
from typing import Any

_request_id = contextvars.ContextVar("request_id", default=None)
event_id = contextvars.ContextVar("event_id", default=None)
incident_id = contextvars.ContextVar("incident_id", default=None)
workspace_id = contextvars.ContextVar("workspace_id", default=None)
ai_request_id = contextvars.ContextVar("ai_request_id", default=None)
decision_id = contextvars.ContextVar("decision_id", default=None)
execution_id = contextvars.ContextVar("execution_id", default=None)

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~-]+"),
    re.compile(r"(?i)([?&](?:token|access_token|api_key|key|secret|password)=)[^&\s]+"),
    re.compile(r"(?i)(\b(?:api[_-]?key|secret|password|token|jwt)\b\s*[:=]\s*)[^\s,;]+"),
)


def new_id() -> str:
    return uuid.uuid4().hex


def set_request_context(*, request: str | None = None, workspace: str | None = None, **ids: str | None) -> dict[Any, contextvars.Token]:
    tokens: dict[Any, contextvars.Token] = {}
    if request is not None:
        tokens[_request_id] = _request_id.set(request)
    if workspace is not None:
        tokens[workspace_id] = workspace_id.set(workspace)
    for name, value in ids.items():
        var = globals().get(name + "_id")
        if isinstance(var, contextvars.ContextVar) and value is not None:
            tokens[var] = var.set(value)
    return tokens


def reset_request_context(tokens: dict[Any, contextvars.Token]) -> None:
    for var, token in reversed(list(tokens.items())):
        var.reset(token)


def get_request_id() -> str | None:
    return _request_id.get()


def context_ids() -> dict[str, str | None]:
    return {
        "request_id": _request_id.get(),
        "event_id": event_id.get(),
        "incident_id": incident_id.get(),
        "workspace_id": workspace_id.get(),
        "ai_request_id": ai_request_id.get(),
        "decision_id": decision_id.get(),
        "execution_id": execution_id.get(),
    }


def redact_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    result = value
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(lambda m: m.group(1) + "[REDACTED]", result)
    return result


def scrub(value: Any) -> Any:
    if isinstance(value, dict):
        sensitive = {"authorization", "token", "access_token", "refresh_token", "api_key", "apikey", "secret", "password", "jwt", "cookie", "credential", "credentials"}
        return {k: "[REDACTED]" if str(k).lower() in sensitive else scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, tuple):
        return tuple(scrub(v) for v in value)
    return redact_text(value)
