"""Configuration settings for HawkEye SOC backend."""

import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")


class Settings:
    APP_NAME: str = "HawkEye SOC"
    ENV: str = os.getenv("ENV", "development")
    FRONTEND_ORIGIN: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    FRONTEND_ORIGINS: str = os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
    )
    DEMO_MODE: bool = os.getenv("DEMO_MODE", "false").lower() in {"1", "true", "yes"}

    # ------------------------------------------------------------------
    # Authentication (hardened, fail-closed in production)
    # ------------------------------------------------------------------
    # Production MUST authenticate. AUTH_REQUIRED defaults to true whenever
    # ENV=production, and validate_security_settings() refuses to start the
    # service if it was explicitly disabled there. The development demo
    # fallback (dev-user) is unreachable in production.
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))
    _AUTH_REQUIRED_RAW: str = os.getenv("AUTH_REQUIRED", "")
    AUTH_REQUIRED: bool = (
        _AUTH_REQUIRED_RAW.lower() in {"1", "true", "yes"}
        if _AUTH_REQUIRED_RAW
        else ENV == "production"
    )
    AUTH_USERS_JSON: str = os.getenv("AUTH_USERS_JSON", "")
    JWT_ISSUER: str = os.getenv("JWT_ISSUER", "")
    JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE", "")
    # RBAC roles:
    #   viewer   — read only
    #   analyst  — investigate / analyze
    #   operator — execute approved operational actions
    #   admin    — administrative operations
    AUTH_ROLES = frozenset({"admin", "analyst", "operator", "viewer"})

    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
    CORRELATION_WINDOW_MINUTES: int = int(os.getenv("CORRELATION_WINDOW_MINUTES", "30"))
    MODEL_PATH: str = os.getenv(
        "MODEL_PATH",
        os.path.join(os.path.dirname(__file__), "ml", "root_cause_model.pkl"),
    )
    SKLEARN_VERSION: str = "1.8.0"
    MAX_BATCH_SIZE: int = int(os.getenv("MAX_BATCH_SIZE", "100"))
    MAX_RAW_LOG_CHARS: int = int(os.getenv("MAX_RAW_LOG_CHARS", "20000"))
    MAX_DESCRIPTION_CHARS: int = int(os.getenv("MAX_DESCRIPTION_CHARS", "10000"))
    MAX_METADATA_BYTES: int = int(os.getenv("MAX_METADATA_BYTES", "32768"))
    AI_RATE_LIMIT_PER_MINUTE: int = int(os.getenv("AI_RATE_LIMIT_PER_MINUTE", "30"))
    ALERTS_CSV_PATH: str = os.getenv(
        "ALERTS_CSV_PATH",
        os.path.join(os.path.dirname(__file__), "data", "alerts.csv"),
    )
    # Gemini AI provider (optional; DEMO_MODE uses the deterministic demo provider
    # by default, while Local/Gemini remain explicitly selectable). No key is required at startup.
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
    GEMINI_TIMEOUT_SECONDS: float = float(os.getenv("GEMINI_TIMEOUT_SECONDS", "60"))
    GEMINI_API_BASE: str = os.getenv(
        "GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta"
    )
    EVENTBUS_MAX_QUEUE_SIZE: int = int(os.getenv("EVENTBUS_MAX_QUEUE_SIZE", "1000"))
    EVENTBUS_ENQUEUE_TIMEOUT_SECONDS: float = float(os.getenv("EVENTBUS_ENQUEUE_TIMEOUT_SECONDS", "5"))


settings = Settings()


def validate_security_settings() -> None:
    """Fail closed for production; refuse obviously insecure algorithms always."""
    if settings.JWT_ALGORITHM not in {"HS256", "HS384", "HS512"}:
        raise RuntimeError("Unsupported JWT algorithm")

    if settings.ENV == "production":
        if not settings.AUTH_REQUIRED:
            raise RuntimeError(
                "AUTH_REQUIRED cannot be disabled in production: "
                "authentication must fail closed"
            )
        if len(settings.JWT_SECRET.encode("utf-8")) < 32:
            raise RuntimeError(
                "JWT_SECRET must be configured with at least 32 bytes "
                "when authentication is enabled"
            )
        if not settings.AUTH_USERS_JSON:
            raise RuntimeError(
                "AUTH_USERS_JSON must be configured when authentication is enabled"
            )

    origins = [origin.strip() for origin in settings.FRONTEND_ORIGINS.split(",") if origin.strip()]
    if "*" in origins:
        raise RuntimeError("Wildcard CORS origin cannot be used with credentials")
    if settings.ENV == "production" and not origins:
        raise RuntimeError("Production CORS requires explicit allowed origins")
    if not settings.DATABASE_URL:
        raise RuntimeError("DATABASE_URL must be configured; PostgreSQL is required for the application")
    if settings.ENV == "production" and not settings.DATABASE_URL.startswith(("postgresql://", "postgresql+psycopg://", "postgresql+psycopg2://")):
        raise RuntimeError("Production persistence requires PostgreSQL DATABASE_URL")
    for name in ("MAX_BATCH_SIZE", "MAX_RAW_LOG_CHARS", "MAX_DESCRIPTION_CHARS", "MAX_METADATA_BYTES", "EVENTBUS_MAX_QUEUE_SIZE", "AI_RATE_LIMIT_PER_MINUTE"):
        if getattr(settings, name) <= 0:
            raise RuntimeError(f"{name} must be greater than zero")
    if settings.EVENTBUS_ENQUEUE_TIMEOUT_SECONDS <= 0:
        raise RuntimeError("EVENTBUS_ENQUEUE_TIMEOUT_SECONDS must be greater than zero")
