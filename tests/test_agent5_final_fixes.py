from __future__ import annotations
import asyncio
import threading
from sqlalchemy import select

from app.core.event_bus import EventBus
from app.core.audit import audit_log
from app.db import close_db, reset_db_for_tests, get_session
from app.db.models import EventDispatch, AuditLog
from app.repositories.soc_repository import _forward_publish


def test_durable_event_subscriber_failure_stays_queued(tmp_path, monkeypatch):
    db = tmp_path / "outbox-failure.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    bus = EventBus()
    async def boom(_t, _p): raise RuntimeError("subscriber failed")
    async def scenario():
        await bus.subscribe("incident.updated", boom)
        await bus.start()
        monkeypatch.setattr("app.repositories.soc_repository.event_bus", bus)
        _forward_publish("incident.updated", {"incident_id": "INC-1"}, "tenant-a")
        await asyncio.sleep(0)
        await bus.stop()
    asyncio.run(scenario())
    with get_session() as s:
        row = s.scalar(select(EventDispatch).where(EventDispatch.workspace_id == "tenant-a"))
        assert row is not None and row.status == "QUEUED"
    close_db()


def test_event_success_delivery_transitions_to_delivered(tmp_path, monkeypatch):
    db = tmp_path / "outbox-success.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    bus = EventBus()
    async def good(_t, p):
        from app.db import PersistentStateRepository
        PersistentStateRepository().mark_dispatch("tenant-a", p["event_id"], "DELIVERED")
    async def scenario():
        await bus.subscribe("incident.updated", good)
        await bus.start()
        monkeypatch.setattr("app.repositories.soc_repository.event_bus", bus)
        _forward_publish("incident.updated", {"incident_id": "INC-2"}, "tenant-a")
        await asyncio.sleep(0)
        await bus.stop()
    asyncio.run(scenario())
    with get_session() as s:
        row = s.scalar(select(EventDispatch).where(EventDispatch.workspace_id == "tenant-a"))
        assert row is not None and row.status == "DELIVERED"
    close_db()


def test_event_duplicate_ids_are_idempotent_and_overflow_retryable():
    async def scenario():
        bus = EventBus(max_queue_size=1)
        gate = asyncio.Event(); seen = []
        async def slow(_t, p):
            seen.append(p["event_id"]); await gate.wait()
        await bus.subscribe("incident.updated", slow)
        await bus.start()
        bus.publish_nowait("incident.updated", {"event_id": "E1"})
        await asyncio.sleep(0)
        # Fill the bounded queue; E2 must remain retryable after overflow.
        bus._queue.put_nowait(("incident.updated", {"event_id": "FILL"}, None))
        try:
            try:
                bus.publish_nowait("incident.updated", {"event_id": "E2"})
            except RuntimeError:
                pass
            else:
                raise AssertionError("expected bounded enqueue failure")
            gate.set(); await bus._queue.join()
            bus.publish_nowait("incident.updated", {"event_id": "E2"})
            bus.publish_nowait("incident.updated", {"event_id": "E2"})
            await bus._queue.join(); await bus.stop()
            return seen
        finally:
            gate.set()
    seen = asyncio.run(scenario())
    assert seen.count("E2") == 1


def test_undelivered_dispatch_is_restart_recoverable(tmp_path, monkeypatch):
    db = tmp_path / "outbox-restart.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    from app.db import PersistentStateRepository
    store = PersistentStateRepository()
    store.queue_dispatch("tenant-a", "E-RECOVER", "incident.updated", {"event_id":"E-RECOVER", "workspace":"tenant-a"})
    assert store.queued_dispatches() == [("tenant-a", "E-RECOVER", "incident.updated", {"event_id":"E-RECOVER", "workspace":"tenant-a"})]
    delivered = []
    async def scenario():
        bus = EventBus()
        async def good(_t, p): delivered.append(p["event_id"])
        await bus.subscribe("incident.updated", good); await bus.start()
        ok = await bus.publish("incident.updated", {"event_id":"E-RECOVER", "workspace":"tenant-a"})
        if ok: store.mark_dispatch("tenant-a", "E-RECOVER", "DELIVERED")
        await bus.stop()
    asyncio.run(scenario())
    assert delivered == ["E-RECOVER"]
    assert store.queued_dispatches() == []
    close_db()


def test_audit_hash_chain_serializes_concurrent_writes(tmp_path, monkeypatch):
    db = tmp_path / "audit-chain.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    barrier = threading.Barrier(16)
    errors = []
    def worker(i):
        try:
            barrier.wait(timeout=5)
            audit_log.record(f"CONCURRENT-{i}", workspace_id="chain-concurrent")
        except Exception as exc:
            errors.append(exc)
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)
    assert not errors
    with get_session() as s:
        rows = s.scalars(select(AuditLog).where(AuditLog.workspace_id == "chain-concurrent").order_by(AuditLog.pk)).all()
        assert len(rows) == 16
        assert rows[0].previous_hash == ""
        for prev, row in zip(rows, rows[1:]):
            assert row.previous_hash == prev.record_hash
    close_db()


def test_application_startup_retries_queued_dispatch_after_failure(tmp_path, monkeypatch):
    db = tmp_path / "outbox-lifespan.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    from app.db import PersistentStateRepository
    store = PersistentStateRepository()
    store.queue_dispatch("tenant-a", "E-START", "incident.updated", {"event_id":"E-START", "workspace":"tenant-a"})
    from app.main import app, lifespan, manager
    calls = []
    async def fail_publish(_topic, _payload):
        calls.append("fail")
        raise RuntimeError("websocket failure")
    monkeypatch.setattr(manager, "publish", fail_publish)
    async def first():
        async with lifespan(app):
            await asyncio.sleep(0)
    asyncio.run(first())
    assert store.queued_dispatches()[0][1] == "E-START"

    async def good_publish(_topic, payload):
        calls.append(payload["event_id"])
    monkeypatch.setattr(manager, "publish", good_publish)
    async def second():
        async with lifespan(app):
            await asyncio.sleep(0)
    asyncio.run(second())
    assert store.queued_dispatches() == []
    assert calls.count("E-START") == 1
    close_db()
