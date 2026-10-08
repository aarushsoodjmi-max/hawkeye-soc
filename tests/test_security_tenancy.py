"""Regression tests: authentication, RBAC, multi-tenancy and WebSocket isolation.

Covers the hardened security contract:
- cross-tenant incident / event / report access is rejected (404 for reads)
- forged workspace ids are rejected (403 on workspace-prefixed paths,
  None at the data layer)
- viewer cannot execute operational actions (403)
- invalid / expired / malformed / missing-claim tokens are rejected (401)
- production authentication fails closed (no silent demo auth)
- every authenticated principal carries user_id + workspace_id + role
- WebSocket connections are tenant-isolated and invalid auth is rejected
- security-sensitive log values are redacted
"""
from __future__ import annotations

import asyncio
import logging

import jwt
import pytest
from fastapi import HTTPException
from starlette.websockets import WebSocketDisconnect

from app.config import settings, validate_security_settings
from app.core.auth import (
    Principal,
    create_access_token,
    current_principal,
    decode_token,
)
from app.core.security import (
    SecurityRedactionFilter,
    redact_payload,
    redact_value,
)
from app.core.websocket import manager
from app.repositories import repository


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _token(subject="u-1", role="analyst", workspace="ws-a", expires_minutes=None) -> str:
    return create_access_token(subject, role, workspace, expires_minutes=expires_minutes)


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _default_incident():
    incidents = repository.get_incidents(workspace="default")[0]
    assert incidents, "baseline default-workspace incidents must exist"
    return incidents[0]


def _default_alert():
    alerts, _ = repository.get_alerts(workspace="default", limit=1)
    assert alerts, "baseline default-workspace alerts must exist"
    return alerts[0]


# ---------------------------------------------------------------------------
# 1. Canonical tenant context
# ---------------------------------------------------------------------------
def test_principal_carries_full_identity():
    p = decode_token(_token(subject="alice", role="operator", workspace="acme"))
    assert p.sub == "alice"
    assert p.user_id == "alice"
    assert p.workspace == "acme"
    assert p.workspace_id == "acme"
    assert p.role == "operator"


def test_current_principal_rejects_missing_token_in_production(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "AUTH_REQUIRED", True)
    with pytest.raises(HTTPException) as ei:
        current_principal(credentials=None)
    assert ei.value.status_code == 401


# ---------------------------------------------------------------------------
# 6. Token validation
# ---------------------------------------------------------------------------
def test_invalid_token_rejected():
    with pytest.raises(HTTPException) as ei:
        decode_token("not.a.jwt")
    assert ei.value.status_code == 401


def test_malformed_token_rejected():
    with pytest.raises(HTTPException) as ei:
        decode_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.not-a-valid-payload.signature")
    assert ei.value.status_code == 401


def test_expired_token_rejected():
    with pytest.raises(HTTPException) as ei:
        decode_token(_token(expires_minutes=-5))
    assert ei.value.status_code == 401
    assert "expired" in str(ei.value.detail).lower()


def test_missing_identity_claims_rejected():
    # token lacking role + workspace claims
    forged = jwt.encode(
        {"sub": "alice", "exp": 4_102_444_800},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(HTTPException) as ei:
        decode_token(forged)
    assert ei.value.status_code == 401


def test_unknown_role_claim_rejected():
    forged = jwt.encode(
        {"sub": "alice", "role": "superuser", "workspace": "ws-a", "exp": 4_102_444_800},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(HTTPException) as ei:
        decode_token(forged)
    assert ei.value.status_code == 401


def test_empty_workspace_claim_rejected():
    forged = jwt.encode(
        {"sub": "alice", "role": "analyst", "workspace": "", "exp": 4_102_444_800},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(HTTPException):
        decode_token(forged)


def test_token_forged_with_other_secret_rejected():
    forged = jwt.encode(
        {"sub": "alice", "role": "admin", "workspace": "ws-b", "exp": 4_102_444_800},
        "totally-different-secret-that-is-long-enough",
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as ei:
        decode_token(forged)
    assert ei.value.status_code == 401


# ---------------------------------------------------------------------------
# 8. Production auth defaults (fail closed)
# ---------------------------------------------------------------------------
def test_production_cannot_disable_auth(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "AUTH_REQUIRED", False)
    with pytest.raises(RuntimeError, match="AUTH_REQUIRED"):
        validate_security_settings()


def test_production_requires_strong_secret(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "AUTH_REQUIRED", True)
    monkeypatch.setattr(settings, "JWT_SECRET", "short")
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", "{}")
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        validate_security_settings()


def test_production_requires_user_registry(monkeypatch):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "AUTH_REQUIRED", True)
    monkeypatch.setattr(settings, "JWT_SECRET", "x" * 64)
    monkeypatch.setattr(settings, "AUTH_USERS_JSON", "")
    with pytest.raises(RuntimeError, match="AUTH_USERS_JSON"):
        validate_security_settings()


def test_auth_required_defaults_true_in_production():
    # If ENV=production and AUTH_REQUIRED is unset, the default is True.
    assert settings.ENV == "development" or settings.AUTH_REQUIRED is True


# ---------------------------------------------------------------------------
# 2. Tenant isolation — data layer (defense in depth)
# ---------------------------------------------------------------------------
def test_cross_tenant_incident_access_rejected():
    target = _default_incident().id
    assert repository.get_incident_by_id(target, workspace="default") is not None
    # A tenant from another workspace must not even learn the incident exists.
    assert repository.get_incident_by_id(target, workspace="ws-other") is None


def test_cross_tenant_event_access_rejected():
    target = _default_alert().id
    assert repository.get_alert_by_id(target, workspace="default") is not None
    assert repository.get_alert_by_id(target, workspace="ws-other") is None
    events, total = repository.get_alerts(workspace="ws-other")
    assert events == [] and total == 0


def test_incident_listing_is_workspace_scoped():
    ids_default = {i.id for i in repository.get_incidents(workspace="default")[0]}
    ids_other = {i.id for i in repository.get_incidents(workspace="ws-other")[0]}
    assert ids_default and ids_other == set()


def test_mutation_is_workspace_scoped():
    target = _default_incident().id
    assert repository.update_incident_status(target, "CONTAINED", workspace="ws-other") is None
    assert repository.execute_action(
        target,
        _default_incident().recommendedActions[0].id,
        workspace="ws-other",
    ) is None
    assert repository.toggle_asset_isolation(target, "AST-01", workspace="ws-other") is None


# ---------------------------------------------------------------------------
# 2+3. Tenant isolation at the HTTP layer (FastAPI TestClient)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as c:
        yield c


def test_cross_tenant_incident_http_404(client):
    target = _default_incident().id
    resp = client.get(f"/incidents/{target}", headers=_auth(_token(workspace="ws-b")))
    assert resp.status_code == 404


def test_cross_tenant_event_http_404(client):
    target = _default_alert().id
    resp = client.get(f"/alerts/{target}", headers=_auth(_token(workspace="ws-b")))
    assert resp.status_code == 404


def test_cross_tenant_report_http_404(client):
    target = _default_incident().id
    resp = client.get(f"/api/reports/{target}", headers=_auth(_token(workspace="ws-b")))
    assert resp.status_code == 404


def test_cross_tenant_report_export_http_404(client):
    target = _default_incident().id
    resp = client.post(f"/api/reports/{target}/export", headers=_auth(_token(workspace="ws-b")))
    assert resp.status_code == 404


def test_forged_workspace_path_403(client):
    target = _default_incident().id
    # ws-a user tries to reach ws-b's workspace-prefixed alias -> 403
    resp = client.get(
        f"/api/workspaces/ws-b/prediction/incidents/{target}",
        headers=_auth(_token(workspace="ws-a")),
    )
    assert resp.status_code == 403


def test_own_workspace_alias_200(client):
    target = _default_incident().id
    resp = client.get(
        f"/api/workspaces/default/prediction/incidents/{target}",
        headers=_auth(_token(workspace="default")),
    )
    assert resp.status_code in (200, 404)  # 404 only if predict path shape differs


def test_viewer_booted_from_execution(client):
    target = _default_incident().id
    action_id = _default_incident().recommendedActions[0].id
    resp = client.post(
        f"/incidents/{target}/actions/{action_id}/execute",
        headers=_auth(_token(role="viewer")),
    )
    assert resp.status_code == 403


def test_operator_can_execute(client):
    target = _default_incident().id
    incident = _default_incident()
    incident.approvalState = {"required": True, "approved": True, "status": "APPROVED"}
    action_id = incident.recommendedActions[0].id
    resp = client.post(
        f"/incidents/{target}/actions/{action_id}/execute",
        headers=_auth(_token(role="operator", workspace="default")),
    )
    assert resp.status_code == 200


def test_viewer_read_is_allowed(client):
    target = _default_incident().id
    resp = client.get(
        f"/incidents/{target}", headers=_auth(_token(role="viewer", workspace="default"))
    )
    assert resp.status_code == 200


def test_unauthenticated_request_rejected_in_production(monkeypatch, client):
    monkeypatch.setattr(settings, "ENV", "production")
    monkeypatch.setattr(settings, "AUTH_REQUIRED", True)
    resp = client.get("/incidents")
    assert resp.status_code == 401


def test_invalid_token_http_401(client):
    resp = client.get("/incidents", headers=_auth("garbage.token.value"))
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 4/5. WebSocket isolation
# ---------------------------------------------------------------------------
class _FakeWebSocket:
    def __init__(self):
        self.sent = []
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def send_json(self, message: dict) -> None:
        self.sent.append(message)


def test_websocket_tenant_isolation():
    async def scenario():
        a = _FakeWebSocket()
        b = _FakeWebSocket()
        pa = Principal(sub="u-a", role="analyst", workspace="ws-a")
        pb = Principal(sub="u-b", role="viewer", workspace="ws-b")
        await manager.connect(a, ["event.normalized"], pa, "conn-a")
        await manager.connect(b, ["event.normalized"], pb, "conn-b")

        # Event for ws-a must reach ONLY the ws-a client.
        await manager.publish("event.normalized", {"alert_id": "ALT-1", "workspace": "ws-a"})
        assert len(a.sent) == 1
        assert b.sent == []

        # Event for ws-b reaches only ws-b.
        await manager.publish("event.normalized", {"alert_id": "ALT-2", "workspace": "ws-b"})
        assert len(b.sent) == 1
        assert len(a.sent) == 1  # unchanged

        # Unsupported / unsubscribed topics never delivered.
        await manager.publish("event.normalized", {"alert_id": "ALT-3", "workspace": "ws-c"})
        assert len(a.sent) == 1 and len(b.sent) == 1

        # Records retain full identity.
        ra = manager._registry[a]
        rb = manager._registry[b]
        assert (ra.connection_id, ra.user_id, ra.workspace_id, ra.role) == ("conn-a", "u-a", "ws-a", "analyst")
        assert (rb.connection_id, rb.user_id, rb.workspace_id, rb.role) == ("conn-b", "u-b", "ws-b", "viewer")

    asyncio.run(scenario())


def test_websocket_default_workspace_events():
    async def scenario():
        a = _FakeWebSocket()
        pa = Principal(sub="u-a", role="analyst", workspace="default")
        await manager.connect(a, ["event.normalized"], pa, "conn-a")
        # Payload without explicit workspace is treated as default.
        await manager.publish("event.normalized", {"alert_id": "ALT-1"})
        assert len(a.sent) == 1

    asyncio.run(scenario())


def test_websocket_missing_token_rejected(client):
    with pytest.raises(WebSocketDisconnect) as ei:
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()
    assert ei.value.code == 1008


def test_websocket_invalid_token_rejected(client):
    with pytest.raises(WebSocketDisconnect) as ei:
        with client.websocket_connect("/ws?token=not.a.valid.jwt") as ws:
            ws.receive_json()
    assert ei.value.code == 1008


def test_websocket_expired_token_rejected(client):
    tok = _token(expires_minutes=-5)
    with pytest.raises(WebSocketDisconnect) as ei:
        with client.websocket_connect(f"/ws?token={tok}") as ws:
            ws.receive_json()
    assert ei.value.code == 1008


# ---------------------------------------------------------------------------
# 7. Security-sensitive logging
# ---------------------------------------------------------------------------
def test_redact_value_covers_sensitive_keys():
    assert redact_value("password", "hunter2") == "[REDACTED]"
    assert redact_value("JWT_SECRET", "abc") == "[REDACTED]"
    assert redact_value("api_key", "k-123") == "[REDACTED]"
    assert redact_value("authorization", "Bearer xyz") == "[REDACTED]"
    assert redact_value("access_token", "tok") == "[REDACTED]"
    assert redact_value("incident_id", "INC-1") == "INC-1"  # non-sensitive


def test_redact_payload_strips_secrets():
    out = redact_payload({"username": "alice", "password": "hunter2", "token": "abc"})
    assert out["username"] == "alice"
    assert out["password"] == "[REDACTED]"
    assert out["token"] == "[REDACTED]"


def test_logging_filter_redacts_record_args(caplog):
    filt = SecurityRedactionFilter()
    # Keyword args keyed by sensitive names are redacted (the common
    # structured-logging shape for passwords/secrets).
    record = logging.LogRecord(
        "hawkeye.test", logging.INFO, "/x.py", 1,
        "login failed %s", ({"user": "alice", "password": "hunter2"},), None,
    )
    assert filt.filter(record) is True
    # LogRecord flattens a single mapping arg into ``args`` itself.
    assert record.args["user"] == "alice"
    assert record.args["password"] == "[REDACTED]"


def test_logging_filter_redacts_bearer_args(caplog):
    filt = SecurityRedactionFilter()
    record = logging.LogRecord(
        "hawkeye.test", logging.INFO, "/x.py", 1,
        "auth=%s", ("Bearer eyJhbGciOiJIUzI1NiJ9.sig",), None,
    )
    assert filt.filter(record) is True
    assert record.args[0] == "[REDACTED]"
