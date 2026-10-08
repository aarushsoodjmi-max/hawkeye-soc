"""
Typed error hierarchy for the HawkEye Local AI foundation.

Errors are deliberately typed so orchestrators can react to failure modes
(inference server down, timeout, context too large, invalid model output)
without depending on transport details. No local-model-specific internals
leak through these errors, which keeps the contract provider-neutral
(Local and the future Gemini provider surface the same failures).
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class AiError(Exception):
    """Base class for all Local AI foundation errors."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "ai_error",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.details: Dict[str, Any] = details or {}

    def to_payload(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


# ---------------------------------------------------------------------------
# Inference client (transport layer)
# ---------------------------------------------------------------------------
class InferenceError(AiError):
    """Base class for transport-level failures against the inference server."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "inference_error",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, code=code, details=details)


class InferenceConnectionError(InferenceError):
    def __init__(self, message: str = "Could not connect to the local inference server", details=None):
        super().__init__(message, code="inference_connection_error", details=details)


class InferenceTimeoutError(InferenceError):
    def __init__(self, message: str = "Local inference request timed out", details=None):
        super().__init__(message, code="inference_timeout", details=details)


class InferenceServerError(InferenceError):
    def __init__(
        self,
        message: str = "Local inference server returned an error",
        *,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        out = dict(details or {})
        if status_code is not None:
            out["status_code"] = status_code
        super().__init__(message, code="inference_server_error", details=out)


class MalformedServerResponseError(InferenceError):
    def __init__(self, message: str = "Local inference server returned a malformed response", details=None):
        super().__init__(message, code="malformed_server_response", details=details)


# ---------------------------------------------------------------------------
# Model layer
# ---------------------------------------------------------------------------
class ModelUnavailableError(AiError):
    def __init__(self, message: str = "The configured local model is unavailable", details=None):
        super().__init__(message, code="model_unavailable", details=details)


# ---------------------------------------------------------------------------
# Provider layer
# ---------------------------------------------------------------------------
class ProviderUnavailableError(AiError):
    def __init__(self, message: str = "The AI provider is unavailable", details=None):
        super().__init__(message, code="provider_unavailable", details=details)


class InvalidModelOutputError(AiError):
    """Model output could not be interpreted (not JSON / not an object)."""

    def __init__(self, message: str = "The local model returned output that could not be parsed", details=None):
        super().__init__(message, code="invalid_model_output", details=details)


class ProviderOutputValidationError(InvalidModelOutputError):
    """Model output parsed as JSON but failed the strict AiResponse schema.

    Raised instead of ever passing malformed AI output downstream as trusted
    data.
    """

    def __init__(self, message: str = "The local model returned output that failed validation", details=None):
        super().__init__(message, details=details)
        self.code = "invalid_model_output_validation"


class ContextExceededError(AiError):
    def __init__(self, message: str = "The request exceeds the configured model context length", details=None):
        super().__init__(message, code="context_exceeded", details=details)


class ProviderNotFoundError(AiError):
    def __init__(self, message: str = "No AI provider is registered under the requested name", details=None):
        super().__init__(message, code="provider_not_found", details=details)


# ---------------------------------------------------------------------------
# Orchestration layer
# ---------------------------------------------------------------------------
class AiOrchestrationError(AiError):
    """Raised by the orchestrator when an evidence/provider step fails."""

    def __init__(
        self,
        message: str,
        *,
        provider: Optional[str] = None,
        code: str = "ai_orchestration_error",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        out = dict(details or {})
        if provider is not None:
            out["provider"] = provider
        super().__init__(message, code=code, details=out)
