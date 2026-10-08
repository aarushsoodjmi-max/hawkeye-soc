from __future__ import annotations
import asyncio
import json
import logging
import urllib.error
import pytest
from fastapi import HTTPException

from app.config import settings
from app.core.auth import Principal, create_access_token, decode_token
from app.core.audit import audit_log
from app.core.event_bus import EventBus
from app.core.security import SecurityRedactionFilter
from app.core.websocket import WebSocketManager
from app.modules.ai.providers.gemini import GeminiProvider, GeminiQuotaError
from app.modules.ai.providers.local import build_prompt
from app.modules.ai.contracts.evidence import EvidencePackage
from app.modules.ai.contracts.requests import AiRequest
from app.repositories import repository
from app.repositories.soc_repository import ActionApprovalError
from app.modules.playbooks.service import create_playbook, approve_playbook, execute_playbook


def test_same_incident_id_isolation_survives_restart(tmp_path, monkeypatch):
    db = tmp_path / "same-id.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    from app.db import close_db, reset_db_for_tests
    close_db(); reset_db_for_tests(f"sqlite:///{db}")
    from app.repositories.soc_repository import SocRepository
    repo = SocRepository()
    a, _ = repo.ingest_alerts([{"id":"SAME","title":"A","severity":"HIGH","host":"A","user":"u"}], workspace="a")
    b, _ = repo.ingest_alerts([{"id":"SAME","title":"B","severity":"HIGH","host":"B","user":"u"}], workspace="b")
    assert repo.get_alert_by_id("SAME", workspace="a").title == "A"
    assert repo.get_alert_by_id("SAME", workspace="b").title == "B"
    repo2 = SocRepository()
    assert repo2.get_alert_by_id("SAME", workspace="a").title == "A"
    assert repo2.get_alert_by_id("SAME", workspace="b").title == "B"
    close_db()


def test_legacy_toggle_cannot_bypass_approval():
    inc = repository.get_incidents(workspace="default")[0][0]
    inc.approvalState = {"required": True, "approved": False, "status": "PENDING_APPROVAL"}
    repository._persist_incident(inc, "default")
    with pytest.raises(ActionApprovalError):
        repository.toggle_asset_isolation(inc.id, inc.affectedAssets[0].id, workspace="default")


def test_audit_records_are_tenant_scoped_and_secret_scrubbed():
    aid = audit_log.record("SECURITY_TEST", actor_id="u", role="admin", workspace_id="audit-a", details={"nested":{"token":"super-secret"}, "url":"https://x.test/?token=super-secret"})
    rows = __import__("app.db", fromlist=["PersistentStateRepository"]).PersistentStateRepository().list("audit_logs", "audit-a") if False else None
    from app.db import get_session
    from app.db.models import AuditLog
    from sqlalchemy import select
    with get_session() as session:
        row = session.scalar(select(AuditLog).where(AuditLog.record_id == aid))
        assert row.details["nested"]["token"] == "[REDACTED]"
        assert "super-secret" not in json.dumps(row.details)
        assert row.workspace_id == "audit-a"


def test_audit_hash_chain_is_append_only_shape():
    a1 = audit_log.record("A1", workspace_id="chain-a")
    a2 = audit_log.record("A2", workspace_id="chain-a")
    from app.db import get_session
    from app.db.models import AuditLog
    from sqlalchemy import select
    with get_session() as session:
        rows = session.scalars(select(AuditLog).where(AuditLog.workspace_id == "chain-a").order_by(AuditLog.pk)).all()
        assert rows[-1].previous_hash == rows[-2].record_hash
        assert rows[-1].record_hash


def test_bounded_event_bus_rejects_overflow_without_silent_drop():
    async def run():
        bus = EventBus(max_queue_size=1)
        gate = asyncio.Event()
        async def slow(topic, payload):
            await gate.wait()
        await bus.subscribe("incident.updated", slow)
        await bus.start()
        assert bus._queue is not None
        bus._queue.put_nowait(("incident.updated", {"n": 1}, None))
        await asyncio.sleep(0)
        bus._queue.put_nowait(("incident.updated", {"n": 2}, None))
        with pytest.raises(RuntimeError):
            bus.publish_nowait("incident.updated", {"n": 3})
        gate.set()
        await bus._queue.join()
        await bus.stop()
    asyncio.run(run())


class _WS:
    def __init__(self): self.sent=[]
    async def accept(self): pass
    async def send_json(self, data): self.sent.append(data)


def test_websocket_requires_explicit_tenant_for_non_default_events():
    async def run():
        m = WebSocketManager(); a = _WS(); b = _WS()
        await m.connect(a, ["incident.updated"], Principal(sub="a", role="analyst", workspace="a"), "a")
        await m.connect(b, ["incident.updated"], Principal(sub="b", role="analyst", workspace="b"), "b")
        await m.publish("incident.updated", {"workspace":"a","incident_id":"x"})
        assert len(a.sent)==1 and not b.sent
    asyncio.run(run())


def test_prompt_redacts_secret_like_evidence():
    evidence = EvidencePackage(incident_id="I", workspace_id="default", analyst_notes="https://example.test/?token=TOPSECRET")
    prompt = build_prompt(AiRequest(incident_id="I"), evidence)
    assert "TOPSECRET" not in prompt
    assert "[REDACTED]" in prompt


def test_gemini_retries_transient_quota_without_leaking_key():
    calls=[]
    def transport(url, payload, timeout):
        calls.append(payload)
        if len(calls) < 3:
            raise urllib.error.HTTPError(url, 429, "rate limited", {}, None)
        return {"candidates":[{"content":{"parts":[{"text":"{\"summary\":\"ok\"}"}]}}]}
    p = GeminiProvider(api_key="SECRET-KEY", transport=transport, timeout_seconds=1)
    p._build_prompt(AiRequest(incident_id="I"), EvidencePackage(incident_id="I", workspace_id="default"))
    # _call_model needs valid envelope only; retries are the property under test
    out = p._call_model("x", AiRequest(incident_id="I"))
    assert len(calls) == 3
    assert all("SECRET-KEY" not in json.dumps(x) for x in calls if isinstance(x, dict) and "_transport_metadata" not in x)


def test_auth_rejects_future_iat():
    import jwt
    from datetime import datetime, timedelta, timezone
    claims={"sub":"u","role":"viewer","workspace":"a","iat":datetime.now(timezone.utc)+timedelta(minutes=5),"jti":"j","exp":datetime.now(timezone.utc)+timedelta(hours=1)}
    token=jwt.encode(claims, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(HTTPException): decode_token(token)


def test_rbac_separates_approval_and_execution():
    from fastapi.testclient import TestClient
    from app.main import app
    inc = repository.get_incidents(workspace="default")[0][0]
    pb = create_playbook(inc.id, ["isolate_device"], target=inc.affectedAssets[0].name, workspace_id="default")
    with TestClient(app) as client:
        operator = {"Authorization": "Bearer " + create_access_token("op", "operator", "default")}
        viewer = {"Authorization": "Bearer " + create_access_token("vw", "viewer", "default")}
        r = client.post(f"/api/playbooks/incidents/{inc.id}/playbooks/{pb.playbook_id}/approve", headers=operator)
        assert r.status_code == 403
        r = client.post(f"/api/playbooks/incidents/{inc.id}/playbooks/execute", headers=viewer, json={"playbook_id": pb.playbook_id})
        assert r.status_code == 403


def test_secret_redaction_filter_covers_formatted_log_message(caplog):
    logger = logging.getLogger("agent3.redaction")
    logger.addFilter(SecurityRedactionFilter())
    with caplog.at_level(logging.INFO, logger="agent3.redaction"):
        logger.info("authorization=Bearer SUPERJWT token=TOPSECRET")
    assert all("SUPERJWT" not in r.getMessage() and "TOPSECRET" not in r.getMessage() for r in caplog.records)
