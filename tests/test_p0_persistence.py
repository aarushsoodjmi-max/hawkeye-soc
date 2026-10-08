from __future__ import annotations
import os
from pathlib import Path
import pytest


def test_restart_persists_alerts_incidents(tmp_path, monkeypatch):
    db = tmp_path / "restart.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    from app.db import close_db, reset_db_for_tests
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    from app.repositories.soc_repository import SocRepository
    repo1 = SocRepository()
    payload = {"id":"PERSIST-1","title":"Persistent alert","severity":"HIGH","host":"HOST-P","user":"svc","timestamp":"2026-09-08T00:00:00Z","source":"EDR"}
    alerts, incident_id = repo1.ingest_alerts([payload], workspace="tenant-a")
    assert alerts
    assert repo1.get_alert_by_id("PERSIST-1", workspace="tenant-a") is not None
    repo2 = SocRepository()
    assert repo2.get_alert_by_id("PERSIST-1", workspace="tenant-a") is not None
    assert incident_id is None or repo2.get_incident_by_id(incident_id, workspace="tenant-a") is not None
    close_db()


def test_persistence_is_tenant_scoped(tmp_path, monkeypatch):
    db = tmp_path / "tenant.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    from app.db import close_db, reset_db_for_tests
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    from app.repositories.soc_repository import SocRepository
    repo = SocRepository()
    repo.ingest_alerts([{"id":"SAME-ID","title":"A","severity":"HIGH","host":"A","user":"u","timestamp":"2026-09-08T00:00:00Z"}], workspace="tenant-a")
    repo.ingest_alerts([{"id":"SAME-ID","title":"B","severity":"HIGH","host":"B","user":"u","timestamp":"2026-09-08T00:01:00Z"}], workspace="tenant-b")
    assert repo.get_alert_by_id("SAME-ID", workspace="tenant-a").title == "A"
    assert repo.get_alert_by_id("SAME-ID", workspace="tenant-b").title == "B"
    assert repo.get_alert_by_id("SAME-ID", workspace="tenant-c") is None
    close_db()


def test_duplicate_event_is_idempotent(tmp_path, monkeypatch):
    db = tmp_path / "dedupe.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    from app.db import close_db, reset_db_for_tests
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    from app.repositories.soc_repository import SocRepository
    repo = SocRepository()
    payload = {"id":"DUP-1","title":"Duplicate","severity":"HIGH","host":"HOST","user":"u","timestamp":"2026-09-08T00:00:00Z"}
    first, _ = repo.ingest_alerts([payload], workspace="tenant-a")
    second, _ = repo.ingest_alerts([payload], workspace="tenant-a")
    assert first and second
    assert len([a for a in repo.alerts if a.id == "DUP-1"]) == 1
    close_db()
