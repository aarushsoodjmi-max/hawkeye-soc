"""
Local AI inference configuration.

Follows the existing HawkEye settings convention (app/config.py): a plain
class, environment-variable driven, with safe defaults and validation at
load time. No secrets are hardcoded; an optional API key is read from the
environment only and is excluded from metadata/logs.

Environment variables (prefix ``HAWKEYE_AI_``):

- MODEL                  model name used in requests
- MODEL_PATH             filesystem path/identifier when the model is served locally
- SERVER_URL             base URL of the local inference server
- COMPLETION_ENDPOINT    completion path (default /v1/chat/completions)
- HEALTH_ENDPOINT        health path (default /health)
- REQUEST_FORMAT         chat | completion | generic (inference backend shape)
- CONTEXT_LENGTH         model context window in tokens
- TEMPERATURE            sampling temperature (0..2)
- MAX_TOKENS             maximum output tokens
- DEVICE                 auto | cpu | gpu
- GPU_LAYERS             optional GPU offload layer count (llama.cpp style backends)
- REQUEST_TIMEOUT        total request timeout seconds
- CONNECT_TIMEOUT        connect timeout seconds
- HEALTH_CHECK_TIMEOUT   health probe timeout seconds
- RETRY_MAX_ATTEMPTS     bounded retry count for transient failures
- RETRY_BACKOFF          initial backoff seconds
- RETRY_BACKOFF_FACTOR   exponential backoff multiplier
- RETRY_MAX_BACKOFF      backoff cap in seconds
- API_KEY                optional bearer token (never logged, never in metadata)
"""

from __future__ import annotations

import os
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlparse

_ENV_PREFIX = "HAWKEYE_AI_"


class InferenceSettings:
    """Validated settings for the local inference backend (env-driven)."""

    def __init__(
        self,
        overrides: Optional[Mapping[str, str]] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        env = os.environ if env is None else env

        def get(key: str, default: str) -> str:
            value = (overrides or {}).get(key)
            if value is not None:
                return value
            return env.get(f"{_ENV_PREFIX}{key}", default)

        # --- model ---
        self.model_name: str = get("MODEL", "hawkeye-local-7b")
        self.model_path: str = get("MODEL_PATH", "")
        # --- server ---
        self.server_url: str = get("SERVER_URL", "http://127.0.0.1:8001")
        self.completion_endpoint: str = get("COMPLETION_ENDPOINT", "/v1/chat/completions")
        self.health_endpoint: str = get("HEALTH_ENDPOINT", "/health")
        self.request_format: str = get("REQUEST_FORMAT", "chat")
        # --- generation ---
        self.context_length: int = int(get("CONTEXT_LENGTH", "8192"))
        self.temperature: float = float(get("TEMPERATURE", "0.2"))
        self.max_tokens: int = int(get("MAX_TOKENS", "2048"))
        self.device: str = get("DEVICE", "auto")
        self.gpu_layers: Optional[int] = None
        gpu_layers_raw = get("GPU_LAYERS", "")
        if gpu_layers_raw.strip():
            self.gpu_layers = int(gpu_layers_raw)
        # --- transport ---
        self.request_timeout_seconds: float = float(get("REQUEST_TIMEOUT", "60"))
        self.connect_timeout_seconds: float = float(get("CONNECT_TIMEOUT", "10"))
        self.health_check_timeout_seconds: float = float(get("HEALTH_CHECK_TIMEOUT", "5"))
        # --- retries ---
        self.retry_max_attempts: int = int(get("RETRY_MAX_ATTEMPTS", "3"))
        self.retry_backoff_seconds: float = float(get("RETRY_BACKOFF", "0.5"))
        self.retry_backoff_factor: float = float(get("RETRY_BACKOFF_FACTOR", "2.0"))
        self.retry_max_backoff_seconds: float = float(get("RETRY_MAX_BACKOFF", "30"))
        # --- optional auth (never hardcoded) ---
        api_key = get("API_KEY", "")
        self.api_key: Optional[str] = api_key if api_key.strip() else None

        errors = self._validate()
        if errors:
            joined = "; ".join(errors)
            raise ValueError(f"Invalid HAWKEYE_AI configuration: {joined}")

    # ------------------------------------------------------------------
    def _validate(self) -> list[str]:
        errors: list[str] = []
        if not self.model_name.strip():
            errors.append("MODEL must not be empty")
        try:
            parsed = urlparse(self.server_url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                errors.append(f"SERVER_URL must be an http(s) URL, got {self.server_url!r}")
        except Exception:
            errors.append(f"SERVER_URL is not a valid URL: {self.server_url!r}")
        if self.request_format not in ("chat", "completion", "generic"):
            errors.append(f"REQUEST_FORMAT must be chat|completion|generic, got {self.request_format!r}")
        if not self.completion_endpoint.startswith("/"):
            errors.append("COMPLETION_ENDPOINT must start with '/'")
        if not self.health_endpoint.startswith("/"):
            errors.append("HEALTH_ENDPOINT must start with '/'")
        if self.context_length < 256:
            errors.append(f"CONTEXT_LENGTH must be >= 256, got {self.context_length}")
        if not (0.0 <= self.temperature <= 2.0):
            errors.append(f"TEMPERATURE must be within [0, 2], got {self.temperature}")
        if self.max_tokens < 1:
            errors.append(f"MAX_TOKENS must be >= 1, got {self.max_tokens}")
        if self.max_tokens > self.context_length:
            errors.append(
                f"MAX_TOKENS ({self.max_tokens}) must not exceed CONTEXT_LENGTH ({self.context_length})"
            )
        if self.device not in ("auto", "cpu", "gpu"):
            errors.append(f"DEVICE must be auto|cpu|gpu, got {self.device!r}")
        if self.gpu_layers is not None and self.gpu_layers < 0:
            errors.append(f"GPU_LAYERS must be >= 0, got {self.gpu_layers}")
        if self.request_timeout_seconds <= 0:
            errors.append(f"REQUEST_TIMEOUT must be > 0, got {self.request_timeout_seconds}")
        if self.connect_timeout_seconds <= 0:
            errors.append(f"CONNECT_TIMEOUT must be > 0, got {self.connect_timeout_seconds}")
        if self.health_check_timeout_seconds <= 0:
            errors.append(f"HEALTH_CHECK_TIMEOUT must be > 0, got {self.health_check_timeout_seconds}")
        if self.retry_max_attempts < 1:
            errors.append(f"RETRY_MAX_ATTEMPTS must be >= 1, got {self.retry_max_attempts}")
        if self.retry_backoff_seconds < 0:
            errors.append(f"RETRY_BACKOFF must be >= 0, got {self.retry_backoff_seconds}")
        if self.retry_backoff_factor <= 0:
            errors.append(f"RETRY_BACKOFF_FACTOR must be > 0, got {self.retry_backoff_factor}")
        if self.retry_max_backoff_seconds < 0:
            errors.append(f"RETRY_MAX_BACKOFF must be >= 0, got {self.retry_max_backoff_seconds}")
        return errors

    # ------------------------------------------------------------------
    def metadata(self) -> Dict[str, Any]:
        """Non-sensitive metadata safe for logs/dashboards (excludes api_key)."""
        return {
            "model_name": self.model_name,
            "model_path": self.model_path,
            "server_url": self.server_url,
            "request_format": self.request_format,
            "context_length": self.context_length,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "device": self.device,
            "gpu_layers": self.gpu_layers,
            "request_timeout_seconds": self.request_timeout_seconds,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "retry_max_attempts": self.retry_max_attempts,
        }


# Module-level singleton, created lazily so tests can build isolated instances.
_inference_settings: Optional[InferenceSettings] = None


def get_inference_settings() -> InferenceSettings:
    """Return the process-wide inference settings singleton (validated on creation)."""
    global _inference_settings
    if _inference_settings is None:
        _inference_settings = InferenceSettings()
    return _inference_settings
