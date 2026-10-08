"""
AI orchestrator — the integration point between HawkEye services and the
provider layer.

Flow: Existing services → context builder (evidence) → Orchestrator →
AIProvider (Local or Gemini) → validated AiResponse → HawkEye services.

The orchestrator owns provider selection; business logic stays out of
providers. Errors surface as typed :class:`AiError` exceptions so the web
layer can map them to HTTP responses without knowing provider internals.
"""

from __future__ import annotations

import logging
import uuid
import threading
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

from ..contracts.evidence import EvidencePackage
from ..contracts.requests import AiRequest
from ..contracts.responses import AiResponse
from ..errors import AiError, AiOrchestrationError
from ..providers.base import AIProvider, ProviderRegistry
from .. import get_default_registry
from .context_builder import ContextBuilder
from app.modules.incident_memory.service import memory_service
from app.core.observability import set_request_context, reset_request_context
from app.core.audit import audit_log

logger = logging.getLogger("hawkeye.ai.orchestrator")

try:  # repository is an injectable default; tests never need it
    from app.repositories import repository as _default_repository
except Exception:  # pragma: no cover - import resilience outside the app
    _default_repository = None


class AiOrchestrator:
    def __init__(
        self,
        registry: Optional[ProviderRegistry] = None,
        context_builder: Optional[ContextBuilder] = None,
        default_provider: str | None = None,
    ) -> None:
        self._registry = registry or get_default_registry()
        self._context_builder = context_builder or ContextBuilder(
            repository=_default_repository, memory_service=memory_service
        )
        if default_provider is None:
            from app.config import settings
            default_provider = "demo" if settings.DEMO_MODE else "local"
        self._default_provider = default_provider
        self._rate_lock = threading.RLock()
        self._rate_windows: dict[str, deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------
    def analyze(
        self,
        request: AiRequest,
        evidence: Optional[EvidencePackage] = None,
        provider: Optional[str] = None,
    ) -> AiResponse:
        provider_name = provider or self._default_provider
        rate_key = request.workspace_id or "anonymous"
        now = time.monotonic()
        with self._rate_lock:
            window = self._rate_windows[rate_key]
            while window and now - window[0] >= 60.0:
                window.popleft()
            if len(window) >= __import__("app.config", fromlist=["settings"]).settings.AI_RATE_LIMIT_PER_MINUTE:
                raise AiOrchestrationError("AI rate limit exceeded", provider=provider_name, code="ai_rate_limited", details={"retry_after_seconds": 60})
            window.append(now)
        ai_id = uuid.uuid4().hex
        context_tokens = set_request_context(ai_request_id=ai_id, incident=request.incident_id, workspace=request.workspace_id)
        provider_obj: AIProvider = self._registry.get(provider_name)
        if evidence is None:
            evidence = self._context_builder.build(
                request.incident_id,
                analyst_notes=request.analyst_instructions,
                workspace_id=request.workspace_id,
            )
        if request.workspace_id:
            evidence.assert_workspace(request.workspace_id)
        try:
            response = provider_obj.analyze(request, evidence)
            # Complete the response-side intelligence contract with the existing
            # deterministic decision simulator. This is advisory only: no action
            # is executed and approval remains a separate human gate.
            if evidence.incident is not None:
                from app.modules.decision_engine.service import generate_strategies
                from app.modules.decision_simulator.service import simulate as simulate_decision
                strategies = generate_strategies(evidence.incident)
                options = [
                    {
                        "id": s.id, "name": s.name, "description": s.description,
                        "expected_impact": {
                            "risk_reduction": s.risk_reduction,
                            "downtime_hours": s.downtime_hours,
                            "recovery_time_hours": s.recovery_time_hours,
                            "operational_cost": s.operational_cost,
                        },
                    }
                    for s in strategies
                ]
                # Run the canonical deterministic simulator against canonical
                # incident dependencies. It produces no side effects and cannot
                # authorize execution.
                simulation = simulate_decision(
                    evidence.incident,
                    getattr(evidence.incident, "assetDependencies", {}) or {},
                ).model_dump(mode="json")
                options.append({
                    "id": "DECISION-SIMULATION",
                    "name": "Canonical decision simulation",
                    "description": "Deterministic cascade/downtime/cost simulation; not execution.",
                    "expected_impact": simulation,
                })
                response.simulation_options = options
                # Persist the simulation snapshot when the incident came from
                # the canonical repository, keeping restart behavior intact.
                if request.workspace_id and _default_repository is not None and hasattr(_default_repository, "_persist_incident"):
                    incident_obj = _default_repository.get_incident_by_id(request.incident_id, workspace=request.workspace_id)
                    if incident_obj is not None:
                        incident_obj.latestSimulation = simulation
                        _default_repository._persist_incident(incident_obj, request.workspace_id)
            response.approval_requirement = {"required": True, "mode": "human", "auto_execute": False}
            if request.workspace_id:
                audit_log.record("AI_ANALYSIS", actor_id=None, workspace_id=request.workspace_id, details={"provider": provider_name, "ai_request_id": ai_id}, outcome="SUCCESS")
            return response
        except AiError as exc:
            if request.workspace_id:
                audit_log.record("AI_ANALYSIS", workspace_id=request.workspace_id, details={"provider": provider_name, "ai_request_id": ai_id, "error_code": exc.code}, outcome="FAILED")
            raise
        except Exception as exc:  # defensive: never leak raw provider exceptions
            logger.error("unexpected AI analyze failure provider=%s: %s", provider_name, type(exc).__name__)
            if request.workspace_id:
                audit_log.record("AI_ANALYSIS", workspace_id=request.workspace_id, details={"provider": provider_name, "ai_request_id": ai_id, "error": "unexpected"}, outcome="FAILED")
            raise AiOrchestrationError(
                "AI analysis failed unexpectedly",
                provider=provider_name,
                details={"incident_id": request.incident_id},
            ) from exc
        finally:
            reset_request_context(context_tokens)

    # ------------------------------------------------------------------
    def health(self, provider: Optional[str] = None) -> Dict[str, Any]:
        return self._registry.get(provider or self._default_provider).health()

    def models(self, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        return self._registry.get(provider or self._default_provider).models()

    def provider_names(self) -> List[str]:
        return self._registry.names()


# Module-level singleton following the existing HawkEye convention
# (see incident_memory.service / repositories.soc_repository).
orchestrator = AiOrchestrator()
