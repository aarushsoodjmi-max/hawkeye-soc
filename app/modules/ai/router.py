"""
HTTP integration for the HawkEye AI layer.

The rest of Hawkeye talks to the AI layer through these endpoints and never
depends on whether the active provider is Local or Gemini. Responses are the
validated :class:`AiResponse`; failures map to typed HTTP errors.

Tenant isolation: evidence is assembled here from the incident resolved in
the caller's workspace, then passed directly to the orchestrator — the AI
layer never reads a cross-tenant incident.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response

from app.repositories import repository
from app.core.auth import Principal, current_principal
from app.core.audit import audit_log
from app.core.request_context import ai_request_id_var, incident_id_var
from app.config import settings

from .contracts.requests import AiAnalyzeRequest, AiRequest
from .contracts.responses import AiResponse
from .errors import AiError
from .orchestration.orchestrator import orchestrator
from .orchestration.context_builder import ContextBuilder

logger = logging.getLogger("hawkeye.ai.router")

router = APIRouter(dependencies=[Depends(current_principal)])

class _AIRateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < 60]
            if len(hits) >= limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            # Bound memory even under attacker-controlled identities.
            if len(self._hits) > 10000:
                oldest = sorted(self._hits, key=lambda k: self._hits[k][-1] if self._hits[k] else 0)[:1000]
                for item in oldest:
                    self._hits.pop(item, None)
            return True


_ai_limiter = _AIRateLimiter()


def _status_code(exc: AiError) -> int:
    if exc.code == "provider_not_found":
        return 404
    if exc.code == "context_exceeded":
        return 422
    if exc.code == "ai_rate_limited":
        return 429
    if exc.code in ("invalid_model_output", "invalid_model_output_validation"):
        return 502
    return 503


@router.post("/analyze", response_model=AiResponse, tags=["AI"])
def analyze_incident(payload: AiAnalyzeRequest, response: Response = None, principal: Principal | None = Depends(current_principal)) -> AiResponse:
    if isinstance(principal, Principal) and not _ai_limiter.allow(f"{principal.workspace}:{principal.sub}", settings.AI_RATE_LIMIT_PER_MINUTE):
        raise HTTPException(status_code=429, detail="AI rate limit exceeded")
    ai_id = uuid.uuid4().hex
    ai_tok = ai_request_id_var.set(ai_id)
    inc_tok = incident_id_var.set(payload.incident_id)
    if response is not None:
        response.headers["X-AI-Request-ID"] = ai_id
    request = AiRequest(
        incident_id=payload.incident_id,
        workspace_id=principal.workspace if isinstance(principal, Principal) else None,
        task=payload.task,
        analyst_instructions=payload.analyst_instructions,
        options=payload.options,
    )
    if not isinstance(principal, Principal):
        # Direct Python invocation compatibility for unit tests/internal callers.
        # FastAPI always resolves current_principal before an HTTP request reaches
        # this function, so the branch cannot be used to bypass HTTP security.
        kwargs: dict[str, Any] = {}
    else:
        if principal.role not in {"admin", "analyst"}:
            raise HTTPException(status_code=403, detail=f"Role '{principal.role}' is not permitted")
        # HTTP path — tenant-scoped evidence. A cross-tenant incident is
        # indistinguishable from a missing one (404).
        incident = repository.get_incident_by_id(payload.incident_id, workspace=principal.workspace)
        if incident is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "invalid_request", "message": f"incident {payload.incident_id!r} not found"},
            )
        kwargs = {
            "evidence": ContextBuilder().build_from_incident(
                incident, analyst_notes=request.analyst_instructions, workspace_id=principal.workspace
            )
        }
    try:
        result = orchestrator.analyze(request, provider=payload.provider, **kwargs)
        try:
            audit_log.record("AI_ANALYSIS", actor_id=principal.sub if isinstance(principal, Principal) else None, role=principal.role if isinstance(principal, Principal) else None, workspace_id=principal.workspace if isinstance(principal, Principal) else None, outcome="SUCCESS", details={"provider": payload.provider or "local", "ai_request_id": ai_id})
        except Exception as audit_exc:
            logger.error("AI audit persistence failed incident=%s", payload.incident_id, exc_info=audit_exc)
        return result
    except AiError as exc:
        logger.info("ai analyze failed incident=%s code=%s", payload.incident_id, exc.code)
        raise HTTPException(status_code=_status_code(exc), detail=exc.to_payload()) from exc
    except ValueError as exc:
        message = str(exc)
        status = 404 if "not found" in message else 400
        raise HTTPException(
            status_code=status,
            detail={"code": "invalid_request", "message": message},
        ) from exc
    finally:
        ai_request_id_var.reset(ai_tok)
        incident_id_var.reset(inc_tok)


@router.get("/health", tags=["AI"])
def ai_health(provider: str = "local") -> dict:
    try:
        return orchestrator.health(provider=provider)
    except AiError as exc:
        raise HTTPException(status_code=_status_code(exc), detail=exc.to_payload()) from exc


@router.get("/models", tags=["AI"])
def ai_models(provider: str = "local") -> list:
    try:
        return orchestrator.models(provider=provider)
    except AiError as exc:
        raise HTTPException(status_code=_status_code(exc), detail=exc.to_payload()) from exc
