"""
Transport layer for the local inference server.

The transport is independent from business logic: it builds requests, parses
responses, enforces connection/read timeouts and performs bounded retries for
transient failures only. It never silently falls back to another backend and
returns clear typed errors (see :mod:`app.modules.ai.errors`) to the
provider/orchestrator.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Protocol

import httpx

from ..errors import (
    ContextExceededError,
    InferenceConnectionError,
    InferenceServerError,
    InferenceTimeoutError,
    MalformedServerResponseError,
)
from .config import InferenceSettings, get_inference_settings

logger = logging.getLogger("hawkeye.ai.inference.client")


class InferenceTransport(Protocol):
    """Transport abstraction so tests never need a real server."""

    def post_json(self, url: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]: ...

    def get_json(self, url: str, timeout: float) -> Dict[str, Any]: ...


class HttpxTransport:
    """Default HTTP/JSON transport backed by httpx."""

    def __init__(self, settings: InferenceSettings) -> None:
        self._settings = settings
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if settings.api_key:
            headers["Authorization"] = f"Bearer {settings.api_key}"
        self._client = httpx.Client(
            base_url=settings.server_url.rstrip("/"),
            headers=headers,
            timeout=httpx.Timeout(
                connect=settings.connect_timeout_seconds,
                read=settings.request_timeout_seconds,
                write=settings.request_timeout_seconds,
                pool=settings.connect_timeout_seconds,
            ),
        )

    def post_json(self, url: str, payload: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        try:
            response = self._client.post(url, json=payload, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise InferenceTimeoutError(details={"url": url}) from exc
        except httpx.HTTPError as exc:
            raise InferenceConnectionError(details={"url": url}) from exc
        return _decode(response, url)

    def get_json(self, url: str, timeout: float) -> Dict[str, Any]:
        try:
            response = self._client.get(url, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise InferenceTimeoutError(details={"url": url}) from exc
        except httpx.HTTPError as exc:
            raise InferenceConnectionError(details={"url": url}) from exc
        return _decode(response, url)


def _decode(response: httpx.Response, url: str) -> Dict[str, Any]:
    status = response.status_code
    if status == 413:
        raise ContextExceededError(details={"url": url, "status_code": status})
    if status == 429 or status >= 500:
        raise InferenceServerError(status_code=status, details={"url": url})
    if status >= 400:
        # Only the status and a short classifier are used; the body is never
        # logged (sensitive data in logs is forbidden).
        body = ""
        try:
            body = response.text or ""
        except Exception:  # pragma: no cover - httpx text errors are rare
            body = ""
        lowered = body[:400].lower()
        if status == 400 and any(k in lowered for k in ("context", "token", "too large")):
            raise ContextExceededError(details={"url": url, "status_code": status})
        raise InferenceServerError(status_code=status, details={"url": url})
    try:
        data = response.json()
    except ValueError as exc:
        raise MalformedServerResponseError(details={"url": url}) from exc
    if not isinstance(data, dict):
        raise MalformedServerResponseError(details={"url": url, "reason": "non-object response"})
    return data


def _retryable_status(status_code: Optional[int]) -> bool:
    if status_code is None:
        return False
    return status_code == 429 or status_code >= 500


def _pick_content(data: Dict[str, Any]) -> str:
    for key in ("content", "response", "output", "text", "completion"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value
    # Generic backends may return the structured answer object directly.
    if "summary" in data:
        return json.dumps(data, ensure_ascii=False)
    raise MalformedServerResponseError(details={"reason": "no recognizable content field"})


@dataclass
class InferenceResult:
    content: str
    usage: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


class InferenceClient:
    """Bounded-retry JSON client for the configurable local inference server."""

    def __init__(
        self,
        settings: Optional[InferenceSettings] = None,
        transport: Optional[InferenceTransport] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._settings = settings or get_inference_settings()
        self._transport = transport or HttpxTransport(self._settings)
        self._sleep = sleep

    # ------------------------------------------------------------------
    @property
    def settings(self) -> InferenceSettings:
        return self._settings

    def generate(self, prompt: str) -> InferenceResult:
        if not prompt or not prompt.strip():
            raise ValueError("prompt must not be empty")
        payload = self._build_payload(prompt)
        url = self._settings.completion_endpoint
        attempts = self._settings.retry_max_attempts

        for attempt in range(1, attempts + 1):
            try:
                data = self._transport.post_json(
                    url, payload, timeout=self._settings.request_timeout_seconds
                )
            except ContextExceededError:
                raise
            except MalformedServerResponseError:
                raise  # non-transient
            except InferenceServerError as exc:
                if not _retryable_status(exc.details.get("status_code")):
                    raise
                logger.warning(
                    "inference server error (attempt %d/%d) status=%s",
                    attempt, attempts, exc.details.get("status_code"),
                )
                if attempt == attempts:
                    raise
                self._sleep(self._retry_delay(attempt))
            except (InferenceConnectionError, InferenceTimeoutError) as exc:
                logger.warning(
                    "inference transport failure (attempt %d/%d) code=%s",
                    attempt, attempts, exc.code,
                )
                if attempt == attempts:
                    raise
                self._sleep(self._retry_delay(attempt))
            else:
                content, usage = self._extract_content(data)
                logger.info(
                    "inference success (model=%s format=%s)",
                    self._settings.model_name, self._settings.request_format,
                )
                return InferenceResult(content=content, usage=usage, raw=data)

        raise InferenceConnectionError("inference failed after all retries")  # pragma: no cover

    def health(self) -> Dict[str, Any]:
        """Non-raising health probe: returns a dict with an ok flag."""
        settings = self._settings
        try:
            data = self._transport.get_json(settings.health_endpoint, timeout=settings.health_check_timeout_seconds)
        except (InferenceConnectionError, InferenceTimeoutError, InferenceServerError,
                MalformedServerResponseError, ContextExceededError) as exc:
            return {"ok": False, "error": exc.code, "message": exc.message}
        status = str(data.get("status", "ok")) if isinstance(data, dict) else "ok"
        return {"ok": True, "status": status}

    # ------------------------------------------------------------------
    def _build_payload(self, prompt: str) -> Dict[str, Any]:
        s = self._settings
        base: Dict[str, Any] = {
            "model": s.model_name,
            "temperature": s.temperature,
            "max_tokens": s.max_tokens,
        }
        if s.request_format == "chat":
            base["messages"] = [{"role": "user", "content": prompt}]
            base["stream"] = False
        else:
            base["prompt"] = prompt
        return base

    def _extract_content(self, data: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        s = self._settings
        if s.request_format == "chat":
            try:
                content = data["choices"][0]["message"].get("content", "")
            except (KeyError, IndexError, TypeError) as exc:
                raise MalformedServerResponseError(
                    details={"reason": "missing choices[0].message.content"}
                ) from exc
        elif s.request_format == "completion":
            try:
                content = data["choices"][0].get("text", "")
            except (KeyError, IndexError, TypeError) as exc:
                raise MalformedServerResponseError(
                    details={"reason": "missing choices[0].text"}
                ) from exc
        else:  # generic
            content = _pick_content(data)
        if not isinstance(content, str) or not content.strip():
            raise MalformedServerResponseError(details={"reason": "empty content"})
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return content, usage

    def _retry_delay(self, attempt: int) -> float:
        s = self._settings
        delay = s.retry_backoff_seconds * (s.retry_backoff_factor ** (attempt - 1))
        return min(delay, s.retry_max_backoff_seconds)
