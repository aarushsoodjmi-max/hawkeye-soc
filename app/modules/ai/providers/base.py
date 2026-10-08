"""Provider abstraction for the HawkEye AI layer.

Every AI backend (the Local provider implemented here, and the future
Gemini provider) implements :class:`AIProvider`. Providers consume the
common request/evidence contracts and return the validated
:class:`AiResponse`; business logic never lives inside a provider.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..contracts.evidence import EvidencePackage
from ..contracts.requests import AiRequest
from ..contracts.responses import AiResponse
from ..errors import ProviderNotFoundError


class AIProvider(ABC):
    """Common interface shared by all AI backends (Local + future Gemini)."""

    name: str = "base"

    @abstractmethod
    def analyze(self, request: AiRequest, evidence: EvidencePackage) -> AiResponse:
        """Run a structured analysis task on the given evidence package."""

    def models(self) -> List[Dict[str, Any]]:
        """Expose backup/model metadata (provider-specific overrides)."""
        return []

    def health(self) -> Dict[str, Any]:
        return {"provider": self.name, "status": "ok"}


class ProviderRegistry:
    """In-process registry of named AI providers.

    The web layer and orchestrator select providers by name via this
    registry, so the rest of Hawkeye never depends on provider internals.
    """

    def __init__(self, providers: Optional[List[AIProvider]] = None) -> None:
        self._providers: Dict[str, AIProvider] = {}
        for provider in providers or []:
            self.register(provider)

    def register(self, provider: AIProvider) -> None:
        if not getattr(provider, "name", ""):
            raise ValueError("provider must define a non-empty name")
        self._providers[provider.name] = provider

    def get(self, name: str) -> AIProvider:
        provider = self._providers.get(name)
        if provider is None:
            raise ProviderNotFoundError(details={"provider": name})
        return provider

    def has(self, name: str) -> bool:
        return name in self._providers

    def names(self) -> List[str]:
        return sorted(self._providers.keys())
