from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from concurrent.futures import TimeoutError as FutureTimeoutError
from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

logger = logging.getLogger("hawkeye.event_bus")

TOPICS = {
    "event.normalized",
    "incident.updated",
    "risk.updated",
    "confidence.updated",
    "playbook.executed",
}

Subscriber = Callable[[str, dict[str, Any]], Awaitable[None] | None]


class EventBus:
    """Application-owned asynchronous, thread-safe in-process event dispatcher.

    Synchronous services enqueue through ``publish_nowait``; the application
    lifespan owns one dispatcher task on its asyncio loop. Events are FIFO and
    are never dispatched by per-event threads or per-event event loops.
    """

    TOPICS = TOPICS

    def __init__(self, max_queue_size: int = 1000, enqueue_timeout_seconds: float = 5.0) -> None:
        if max_queue_size < 1:
            raise ValueError("max_queue_size must be positive")
        self._max_queue_size = max_queue_size
        self._enqueue_timeout_seconds = enqueue_timeout_seconds
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)
        self._subscriber_lock = threading.RLock()
        self._queue: asyncio.Queue[tuple[str, dict[str, Any], asyncio.Future | None]] | None = None
        self._seen_event_ids: deque[str] = deque(maxlen=50000)
        self._inflight_event_ids: set[str] = set()
        self._seen_lock = threading.RLock()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._dispatcher_task: asyncio.Task[Any] | None = None
        self._started = False
        self._stopping = False
        self._failures: list[dict[str, Any]] = []
        self._pending_before_start: deque[tuple[str, dict[str, Any]]] = deque(maxlen=max_queue_size)
        self._pending_lock = threading.RLock()

    async def start(self) -> None:
        if self._started:
            return
        self._loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=self._max_queue_size)
        self._stopping = False
        self._started = True
        self._dispatcher_task = asyncio.create_task(
            self._dispatch_loop(), name="hawkeye-event-dispatcher"
        )
        # Preserve events emitted during application construction/startup.
        with self._pending_lock:
            pending = list(self._pending_before_start)
            self._pending_before_start.clear()
        for topic, payload in pending:
            self._queue.put_nowait((topic, payload, None))

    async def stop(self) -> None:
        if not self._started:
            return
        # Let thread-safe call_soon_threadsafe enqueue callbacks run before
        # closing the acceptance window.
        assert self._queue is not None
        await asyncio.sleep(0)
        self._stopping = True
        # Drain all queued events before shutdown. Subscriber failures are
        # isolated and recorded by _dispatch_one.
        await self._queue.join()
        task = self._dispatcher_task
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self._dispatcher_task = None
        self._queue = None
        self._loop = None
        self._started = False
        self._stopping = False

    async def subscribe(self, topic: str, handler: Subscriber) -> None:
        self._validate_topic(topic)
        with self._subscriber_lock:
            if handler not in self._subscribers[topic]:
                self._subscribers[topic].append(handler)

    async def unsubscribe(self, topic: str, handler: Subscriber) -> None:
        self._validate_topic(topic)
        with self._subscriber_lock:
            if handler in self._subscribers.get(topic, []):
                self._subscribers[topic].remove(handler)

    def get_failures(self) -> list[dict[str, Any]]:
        with self._subscriber_lock:
            return deepcopy(self._failures)

    def clear_failures(self) -> None:
        with self._subscriber_lock:
            self._failures.clear()

    @staticmethod
    def _validate_topic(topic: str) -> None:
        if topic not in TOPICS:
            raise ValueError(f"Unsupported event topic: {topic}")

    def _handlers(self, topic: str) -> list[Subscriber]:
        with self._subscriber_lock:
            return list(self._subscribers.get(topic, []))

    def _record_failure(self, topic: str, payload: dict[str, Any], exc: Exception) -> None:
        with self._subscriber_lock:
            self._failures.append({
                "topic": topic,
                "payload": deepcopy(payload),
                "error": repr(exc),
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            })
        from app.core.observability import scrub
        logger.error("Event subscriber failed for %s: %s", topic, scrub(repr(exc)))

    async def _dispatch_one(self, topic: str, payload: dict[str, Any]) -> bool:
        # Subscribers are invoked in registration order. One failure cannot
        # prevent later subscribers from receiving the event. The boolean is
        # used by durable callers to distinguish enqueue from actual delivery.
        delivered = True
        for handler in self._handlers(topic):
            try:
                result = handler(topic, deepcopy(payload))
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                delivered = False
                self._record_failure(topic, payload, exc)
        return delivered

    async def _dispatch_loop(self) -> None:
        assert self._queue is not None
        while True:
            topic, payload, completion = await self._queue.get()
            try:
                delivered = await self._dispatch_one(topic, payload)
                if completion is not None and not completion.done():
                    completion.set_result(delivered)
            except Exception as exc:  # defensive: _dispatch_one isolates subscriber errors
                if completion is not None and not completion.done():
                    completion.set_exception(exc)
            finally:
                self._queue.task_done()

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        """Enqueue and await delivery through the application dispatcher."""
        self._validate_topic(topic)
        event_payload = deepcopy(payload)
        if not self._started:
            await self.start()

        assert self._queue is not None
        loop = asyncio.get_running_loop()
        completion: asyncio.Future[bool] = loop.create_future()
        self._queue.put_nowait((topic, event_payload, completion))
        return await completion

    def publish_nowait(self, topic: str, payload: dict[str, Any]) -> bool:
        """Thread-safe bounded enqueue; durable callers ack only after subscriber delivery."""
        self._validate_topic(topic)
        event_payload = deepcopy(payload)
        event_id = event_payload.get("event_id")
        event_key = str(event_id) if event_id else None
        if event_key:
            with self._seen_lock:
                if event_key in self._seen_event_ids or event_key in self._inflight_event_ids:
                    return True
                self._inflight_event_ids.add(event_key)

        def accepted() -> bool:
            if event_key:
                with self._seen_lock:
                    self._inflight_event_ids.discard(event_key)
                    self._seen_event_ids.append(event_key)
            return True

        def rejected() -> None:
            if event_key:
                with self._seen_lock:
                    self._inflight_event_ids.discard(event_key)

        try:
            if self._stopping:
                raise RuntimeError("EventBus is shutting down; event was not accepted")
            if not self._started or self._queue is None or self._loop is None:
                handlers = self._handlers(topic)
                if any(inspect.iscoroutinefunction(h) for h in handlers):
                    with self._pending_lock:
                        if len(self._pending_before_start) >= self._max_queue_size:
                            raise RuntimeError("EventBus startup queue is full; event was not accepted")
                        self._pending_before_start.append((topic, event_payload))
                    return accepted()
                for handler in handlers:
                    try:
                        result = handler(topic, deepcopy(event_payload))
                        if inspect.isawaitable(result):
                            with self._pending_lock:
                                if len(self._pending_before_start) >= self._max_queue_size:
                                    raise RuntimeError("EventBus startup queue is full; event was not accepted")
                                self._pending_before_start.append((topic, event_payload))
                            break
                    except Exception as exc:
                        self._record_failure(topic, event_payload, exc)
                return accepted()

            assert self._queue is not None and self._loop is not None
            try:
                running_loop = asyncio.get_running_loop()
            except RuntimeError:
                running_loop = None
            item = (topic, event_payload, None)
            if running_loop is self._loop:
                try:
                    self._queue.put_nowait(item)
                except asyncio.QueueFull as exc:
                    logger.error("EventBus queue full; durable outbox remains queued event_id=%s", event_payload.get("event_id", "unknown"))
                    raise RuntimeError("EventBus queue is full; event remains durable for recovery") from exc
                return accepted()

            future = asyncio.run_coroutine_threadsafe(self._queue.put(item), self._loop)
            try:
                future.result(timeout=self._enqueue_timeout_seconds)
            except FutureTimeoutError as exc:
                future.cancel()
                logger.error("EventBus enqueue timed out; durable outbox remains queued event_id=%s", event_payload.get("event_id", "unknown"))
                raise RuntimeError("EventBus enqueue timed out; event remains durable for recovery") from exc
            return accepted()
        except Exception:
            rejected()
            raise


def _configured_bus() -> EventBus:
    try:
        from app.config import settings
        return EventBus(settings.EVENTBUS_MAX_QUEUE_SIZE, settings.EVENTBUS_ENQUEUE_TIMEOUT_SECONDS)
    except Exception:
        return EventBus()

event_bus = _configured_bus()
