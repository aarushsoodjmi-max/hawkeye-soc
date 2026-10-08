from __future__ import annotations
import os
from app.config import settings
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

_engine: Engine | None = None
_SessionLocal = None


def database_url() -> str:
    url = os.getenv("DATABASE_URL") or settings.DATABASE_URL
    if not url:
        raise RuntimeError("DATABASE_URL is required")
    if settings.ENV == "production" and url.startswith("sqlite"):
        raise RuntimeError("SQLite is not permitted in production; configure PostgreSQL DATABASE_URL")
    return url


def get_engine() -> Engine:
    global _engine, _SessionLocal
    url = database_url()
    stale_sqlite = False
    if _engine is not None and str(_engine.url).startswith("sqlite") and url.startswith("sqlite"):
        try:
            db_path = str(_engine.url.database or "")
            stale_sqlite = db_path not in ("", ":memory:") and not os.path.exists(db_path)
        except Exception:
            stale_sqlite = True
    if _engine is None or str(_engine.url) != url or stale_sqlite:
        if _engine is not None:
            _engine.dispose()
        kwargs = {"future": True, "pool_pre_ping": True}
        if url.startswith("sqlite"):
            kwargs.update({"connect_args": {"check_same_thread": False}})
        _engine = create_engine(url, **kwargs)
        _SessionLocal = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_session():
    if _SessionLocal is None:
        get_engine()
    return _SessionLocal()


def init_db() -> None:
    """Initialize the database connection without competing with Alembic.

    SQLite remains self-initializing for local/tests. PostgreSQL schemas are
    owned by Alembic so application startup cannot silently drift the schema
    or make a subsequent migration fail because tables were auto-created.
    Deployment startup runs ``alembic upgrade head`` before Uvicorn.
    """
    engine = get_engine()
    if engine.dialect.name == "sqlite":
        from .models import Base
        Base.metadata.create_all(engine)


def close_db() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


def reset_db_for_tests(url: str | None = None) -> None:
    """Rebind the SQLAlchemy engine; intended for isolated test databases."""
    global _engine, _SessionLocal
    close_db()
    if url:
        os.environ["DATABASE_URL"] = url
    init_db()
