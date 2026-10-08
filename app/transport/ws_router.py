from __future__ import annotations

import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.auth import decode_token
from app.core.websocket import TOPICS, manager

router = APIRouter(tags=["WebSocket"])

_AUTH_CLOSE_CODE = 1008


def _bearer_from_headers(headers) -> str | None:
    value = headers.get("authorization", "")
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return None


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Authenticated, tenant-isolated WebSocket endpoint.

    Identity (``connection_id``, ``user_id``, ``workspace_id``, ``role``) is
    derived exclusively from the bearer token passed as ``?token=`` or an
    ``Authorization: Bearer ...`` header. The client cannot choose its
    workspace: broadcast routing uses the server-side workspace claim, and
    the manager never delivers events belonging to another workspace.

    The token is validated (invalid / malformed / expired / forged claims all
    rejected) and is never logged.
    """
    # Prefer Authorization header. Query-token is compatibility-only because
    # URLs can leak through access logs, browser history, and proxies.
    token = _bearer_from_headers(websocket.headers) or websocket.query_params.get("token")
    if not token:
        await websocket.close(code=_AUTH_CLOSE_CODE, reason="Bearer token required")
        return
    try:
        principal = decode_token(token)
    except Exception:
        await websocket.close(code=_AUTH_CLOSE_CODE, reason="Invalid or expired token")
        return

    try:
        # Raw JWT is no longer needed after principal extraction.
        del token
        raw = websocket.query_params.get("topics", ",".join(sorted(TOPICS)))
        requested = [x.strip() for x in raw.split(",") if x.strip()]
        # Viewers cannot subscribe to operational execution events.
        allowed_topics = TOPICS if principal.role in {"admin", "analyst", "operator"} else TOPICS - {"playbook.executed"}
        unauthorized = [t for t in requested if t in TOPICS and t not in allowed_topics]
        if unauthorized:
            await websocket.close(code=_AUTH_CLOSE_CODE, reason="Topic not authorized")
            return
        topics = [x for x in requested if x in allowed_topics]
        connection_id = str(uuid.uuid4())
        await manager.connect(websocket, topics, principal, connection_id)
    except Exception:
        await manager.disconnect(websocket)
        await websocket.close(code=_AUTH_CLOSE_CODE, reason="WebSocket authorization failed")
        return
    try:
        while True:
            msg = await websocket.receive_json()
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)
        await websocket.close(code=1011)
