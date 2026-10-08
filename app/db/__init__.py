"""Database persistence foundation for Hawkeye.

Production uses PostgreSQL. SQLite is supported for deterministic local/test
runs; production configuration is rejected unless DATABASE_URL is PostgreSQL.
"""
from .session import get_engine, get_session, init_db, close_db, reset_db_for_tests
from .models import Base
from .repositories import PersistentStateRepository

__all__ = ["Base", "get_engine", "get_session", "init_db", "close_db", "reset_db_for_tests", "PersistentStateRepository"]
