from __future__ import annotations

import asyncio
from app.core.event_bus import EventBus


def _register_sync(bus: EventBus, topic: str, handler):
    asyncio.run(bus.subscribe(topic, handler))


def test_normal_async_publish_delivers():
    bus = EventBus()

    async def run():
        seen = []
        await bus.subscribe("incident.updated", lambda t, p: seen.append(p))
        await bus.publish("incident.updated", {"incident_id": "INC-1"})
        return seen

    seen = asyncio.run(run())
    assert len(seen) == 1
    assert seen[0]["incident_id"] == "INC-1"


def test_multiple_subscribers_all_receive():
    bus = EventBus()
    first, second = [], []

    async def run():
        await bus.subscribe("risk.updated", lambda t, p: first.append(p))
        await bus.subscribe("risk.updated", lambda t, p: second.append(p))
        await bus.publish("risk.updated", {"risk_score": 80})

    asyncio.run(run())
    assert first and second
    assert first[0]["risk_score"] == second[0]["risk_score"] == 80


def test_subscriber_failure_is_observable():
    bus = EventBus()

    async def run():
        async def boom(t, p):
            raise RuntimeError("subscriber crashed")

        await bus.subscribe("risk.updated", boom)
        await bus.publish("risk.updated", {"risk_score": 1})
        await bus.publish("risk.updated", {"risk_score": 2})

    asyncio.run(run())
    failures = bus.get_failures()
    assert len(failures) == 2
    assert failures[0]["topic"] == "risk.updated"
    assert "subscriber crashed" in failures[0]["error"]
    assert failures[0]["payload"] == {"risk_score": 1}


def test_publish_nowait_with_running_loop_delivers():
    bus = EventBus()

    async def run():
        seen = []
        await bus.subscribe("event.normalized", lambda t, p: seen.append(p))
        bus.publish_nowait("event.normalized", {"alert_id": "ALT-1"})
        for _ in range(100):
            if seen:
                break
            await asyncio.sleep(0.01)
        return seen

    seen = asyncio.run(run())
    assert seen and seen[0]["alert_id"] == "ALT-1"


def test_publish_nowait_without_running_loop_delivers():
    """Synchronous contexts must not silently discard events."""
    bus = EventBus()
    seen = []

    def handler(topic, payload):
        seen.append(payload)
        return None

    _register_sync(bus, "playbook.executed", handler)
    bus.publish_nowait("playbook.executed", {"playbook_id": "PB-1"})
    assert seen and seen[0]["playbook_id"] == "PB-1"


def test_metadata_preserved_and_payload_not_mutated():
    bus = EventBus()
    captured = []

    async def run():
        async def spy(t, p):
            captured.append(p)

        await bus.subscribe("incident.updated", spy)
        payload = {"incident_id": "INC-9", "metadata": {"tenant": "acme", "workspace": "acme-prod"}}
        await bus.publish("incident.updated", payload)
        payload["incident_id"] = "MUTATED-AFTER-PUBLISH"

    asyncio.run(run())
    assert len(captured) == 1
    assert captured[0]["incident_id"] == "INC-9"
    assert captured[0]["metadata"]["tenant"] == "acme"
    assert captured[0]["metadata"]["workspace"] == "acme-prod"


def test_sync_handler_with_async_publish():
    bus = EventBus()
    seen = []

    async def run():
        await bus.subscribe("confidence.updated", lambda t, p: seen.append(p))
        await bus.publish("confidence.updated", {"unified_confidence": 0.75})

    asyncio.run(run())
    assert seen and seen[0]["unified_confidence"] == 0.75


def test_unsupported_topic_raises():
    bus = EventBus()

    async def subscribe_bad():
        await bus.subscribe("not.a.topic", lambda t, p: None)

    async def publish_bad():
        await bus.publish("not.a.topic", {})

    import pytest
    with pytest.raises(ValueError):
        asyncio.run(subscribe_bad())
    with pytest.raises(ValueError):
        asyncio.run(publish_bad())
