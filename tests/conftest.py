"""Shared test-only environment defaults; production configuration is untouched."""
from pathlib import Path
import sys
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./hawkeye-test.db")
os.environ.setdefault("DEMO_MODE", "true")

ROOT = str(Path(__file__).resolve().parents[1])
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest
from app.config import settings


@pytest.fixture(autouse=True)
def _test_runtime_config(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./hawkeye-test.db")
    monkeypatch.setattr(settings, "DATABASE_URL", "sqlite:///./hawkeye-test.db")
    monkeypatch.setattr(settings, "DEMO_MODE", True)
    monkeypatch.setattr(settings, "JWT_SECRET", "test-secret-for-hawkeye-suite-32-bytes-min")


def pytest_configure(config):
    # Test-only explicit seed operation. Production/live application never
    # seeds on empty-database initialization.
    from app.repositories import repository
    repository.seed_demo_data()
