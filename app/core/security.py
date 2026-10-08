"""Security logging hardening for HawkEye.

Guarantees that passwords, JWT secrets, API keys, authorization headers and
full bearer tokens can never be written to logs, even if a code path
accidentally tries to log them: a logging ``Filter`` redacts any message
argument whose key name is sensitive.
"""

from __future__ import annotations

import logging
from typing import Any

SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "bearer",
        "authorization",
        "api_key",
        "apikey",
        "api-key",
        "jwt",
        "jwt_secret",
        "cookie",
        "session",
        "private_key",
        "credential",
        "credentials",
    }
)

_REDACTED = "[REDACTED]"


def redact_value(key: str, value: Any) -> Any:
    """Return ``[REDACTED]`` for values whose key looks sensitive."""
    if isinstance(key, str) and key.lower() in SENSITIVE_KEYS:
        return _REDACTED
    return value


def redact_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Return a copy of ``payload`` with sensitive keys redacted."""
    if not payload:
        return {}
    return {key: redact_value(key, value) for key, value in payload.items()}


class SecurityRedactionFilter(logging.Filter):
    """Drop-in logging filter that redacts sensitive values in record args.

    Install once per process via :func:`install_security_logging_filter`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, dict):
            record.args = {k: redact_value(k, v) for k, v in args.items()}
        elif isinstance(args, (tuple, list)):
            record.args = tuple(
                redact_value("token", a) if isinstance(a, str) and a.lower().startswith("bearer ") else a
                for a in args
            )
        # Redact secrets embedded directly in formatted log messages as well as
        # structured arguments. This covers propagated child loggers, which may
        # bypass filters installed only on the root logger.
        try:
            rendered = record.getMessage()
            if rendered:
                from app.core.observability import redact_text
                safe = redact_text(rendered)
                if safe != rendered:
                    record.msg = safe
                    record.args = ()
        except Exception:
            # Logging must never become a source of application failure.
            pass
        return True


def install_security_logging_filter() -> None:
    """Attach the redaction filter to the root logger (and the app logger)."""
    root = logging.getLogger()
    filt = next((f for f in root.filters if isinstance(f, SecurityRedactionFilter)), None)
    if filt is None:
        filt = SecurityRedactionFilter()
        root.addFilter(filt)
    # Logger filters are not guaranteed to run for records propagated from
    # descendants; attach to every existing handler too.
    for handler in root.handlers:
        if not any(isinstance(f, SecurityRedactionFilter) for f in handler.filters):
            handler.addFilter(filt)
