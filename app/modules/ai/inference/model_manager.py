"""
Model lifecycle abstraction for the local inference backend.

Responsibilities:

- determine whether the configured local model is available
- expose model metadata and active-model information
- provide model health/status
- support model/version selection through configuration or request override
- validate request size against the configured context length

Deliberately NOT implemented: model marketplaces, automatic production
replacement, and arbitrary model downloads. Model replacement stays an
explicit, configurable operation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..errors import ContextExceededError
from .client import InferenceClient
from .config import InferenceSettings, get_inference_settings

logger = logging.getLogger("hawkeye.ai.model_manager")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ModelInfo:
    model_name: str
    model_path: str
    context_length: int
    max_tokens: int
    device: str
    request_format: str
    available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_path": self.model_path or None,
            "context_length": self.context_length,
            "max_tokens": self.max_tokens,
            "device": self.device,
            "request_format": self.request_format,
            "available": self.available,
        }


class ModelManager:
    """Tracks the active local model and its health/metadata."""

    def __init__(
        self,
        settings: Optional[InferenceSettings] = None,
        client: Optional[InferenceClient] = None,
    ) -> None:
        self._settings = settings or get_inference_settings()
        self._client = client or InferenceClient(self._settings)

    # ------------------------------------------------------------------
    @property
    def active_model(self) -> str:
        return self._settings.model_name

    @property
    def model_path(self) -> str:
        return self._settings.model_path

    # ------------------------------------------------------------------
    def get_model_info(self) -> ModelInfo:
        server_ok = bool(self._client.health().get("ok"))
        return ModelInfo(
            model_name=self._settings.model_name,
            model_path=self._settings.model_path,
            context_length=self._settings.context_length,
            max_tokens=self._settings.max_tokens,
            device=self._settings.device,
            request_format=self._settings.request_format,
            available=server_ok,
        )

    def get_metadata(self) -> Dict[str, Any]:
        """Non-sensitive metadata (never contains the API key)."""
        metadata = self._settings.metadata()
        metadata["available"] = self.get_model_info().available
        return metadata

    def is_available(self) -> bool:
        return bool(self._client.health().get("ok"))

    def health(self) -> Dict[str, Any]:
        server = self._client.health()
        info = self.get_model_info()
        return {
            "provider": "local",
            "status": "ok" if server["ok"] else "unavailable",
            "checked_at": _now_iso(),
            "model": info.to_dict(),
            "server": {"ok": server["ok"], "status": server.get("status")},
        }

    # ------------------------------------------------------------------
    def select_model(self, requested: Optional[str]) -> str:
        """Resolve the model to use: request override wins, else configured."""
        return (requested or "").strip() or self._settings.model_name

    # ------------------------------------------------------------------
    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Rough token heuristic (chars/4). Good enough for context gating."""
        return max(1, (len(text) + 3) // 4)

    def validate_context(
        self, prompt: str, max_output_tokens: Optional[int] = None
    ) -> None:
        """Raise ContextExceededError when the request cannot fit the window."""
        limit = self._settings.context_length
        max_out = max_output_tokens or self._settings.max_tokens
        prompt_tokens = self.estimate_tokens(prompt)
        total = prompt_tokens + max_out
        if total > limit:
            raise ContextExceededError(
                details={
                    "prompt_tokens": prompt_tokens,
                    "max_output_tokens": max_out,
                    "context_length": limit,
                }
            )
