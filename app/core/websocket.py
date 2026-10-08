from __future__ import annotations

import asyncio
from typing import Any

from app.core.auth import Principal

TOPICS = {
    "event.normalized",
    "incident.updated",
    "risk.updated",
    "confidence.updated",
    "playbook.executed",
}

_DEFAULT_WORKSPACE = "default"


class ConnectionRecord:
    """Security identity retained for the whole lifetime of a connection."""

    __slots__ = (
        "connection_id",
        "user_id",
        "workspace_id",
        "role",
        "topics",
        "websocket",
    )

    def __init__(
        self,
        connection_id: str,
        user_id: str,
        workspace_id: str,
        role: str,
        topics: list[str],
        websocket: Any,
    ) -> None:
        self.connection_id = connection_id
        self.user_id = user_id
        self.workspace_id = workspace_id
        self.role = role
        self.topics = set(topics)
        self.websocket = websocket


class WebSocketManager:
    """Tenant-aware WebSocket hub.

    Every connection is bound to a canonical workspace (from its verified
    token). ``publish`` delivers an event ONLY to connections whose
    workspace matches the event payload's ``workspace`` key — a client can
    never subscribe to another tenant's events.
    """

    def __init__(self) -> None:
        self._registry: dict[Any, ConnectionRecord] = {}
        self._lock = asyncio.Lock()

    async def connect(
        self,
        websocket: Any,
        topics: list[str],
        principal: Principal,
        connection_id: str,
    ) -> None:
        await websocket.accept()
        async with self._lock:
            self._registry[websocket] = ConnectionRecord(
                connection_id=connection_id,
                user_id=principal.sub,
                workspace_id=principal.workspace,
                role=principal.role,
                topics=[t for t in topics if t in TOPICS],
                websocket=websocket,
            )

    async def disconnect(self, websocket: Any) -> None:
        async with self._lock:
            self._registry.pop(websocket, None)

    async def publish(self, topic: str, payload: dict) -> None:
        if topic not in TOPICS:
            return
        # Tenant routing: an event is delivered only to connections that
        # belong to the workspace it was published for. Payloads without an
        # explicit workspace key are treated as the default workspace.
        workspace = str(payload.get("workspace", _DEFAULT_WORKSPACE))
        dead = []
        async with self._lock:
            records = list(self._registry.values())
        for rec in records:
            if topic not in rec.topics:
                continue
            if rec.workspace_id != workspace:
                continue
            try:
                await rec.websocket.send_json({"topic": topic, "data": payload})
            except Exception:
                dead.append(rec.websocket)
        for ws in dead:
            await self.disconnect(ws)


manager = WebSocketManager()
