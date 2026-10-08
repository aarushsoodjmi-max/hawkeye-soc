"""HawkEye AI module — Local AI provider & inference foundation.

Layout
------
- contracts/   provider-neutral request/evidence/response schemas
- providers/   AIProvider interface + LocalProvider
- inference/   transport client, model manager, configuration
- orchestration/ context builder + orchestrator (the only layer allowed
                 to touch HawkEye domain data for AI purposes)
- evaluation/  structured response evaluation + benchmark harness
- training/    training-readiness extension points (not coupled to runtime)

The rest of Hawkeye never depends on whether the active provider is Local
or Gemini; both implement ``app.modules.ai.providers.base.AIProvider``.
"""

from __future__ import annotations

from typing import Optional

from .contracts.evidence import EvidencePackage
from .contracts.requests import AiRequest, AiRequestOptions
from .contracts.responses import AiResponse
from .errors import AiError
from .providers.base import AIProvider, ProviderRegistry
from .providers.local import LocalProvider
from .providers.gemini import GeminiProvider

__all__ = [
    "AIProvider",
    "ProviderRegistry",
    "LocalProvider",
    "GeminiProvider",
    "AiRequest",
    "AiRequestOptions",
    "AiResponse",
    "EvidencePackage",
    "AiError",
]


def create_local_provider() -> LocalProvider:
    """Build a LocalProvider wired to the environment-driven settings."""
    return LocalProvider()


def create_gemini_provider() -> GeminiProvider:
    """Build a GeminiProvider; credentials are validated only on inference."""
    return GeminiProvider()


_registry: Optional[ProviderRegistry] = None


def get_default_registry() -> ProviderRegistry:
    """Process-wide provider registry (Local registered by default)."""
    global _registry
    if _registry is None:
        providers = [create_local_provider(), create_gemini_provider()]
        # The deterministic provider is intentionally available only in demo mode.
        # Import lazily to avoid coupling the production provider package to the
        # simulator module during normal startup.
        from app.config import settings
        if settings.DEMO_MODE:
            from .providers.demo import DeterministicDemoProvider
            providers.append(DeterministicDemoProvider())
        _registry = ProviderRegistry(providers)
    return _registry
