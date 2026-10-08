from __future__ import annotations
import hashlib, json, threading
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select, text
from app.core.observability import context_ids, scrub
from app.db import get_session
from app.db.models import AuditLog


class AuditLogger:
    """Append-only, hash-chained security audit log.

    Appends are serialized per workspace. PostgreSQL additionally uses a
    transaction-scoped advisory lock so separate application workers cannot
    fork the chain; SQLite/test deployments use the process-local lock.
    """
    _lock_guard = threading.Lock()
    _workspace_locks: dict[str, threading.Lock] = {}

    @classmethod
    def _workspace_lock(cls, workspace: str) -> threading.Lock:
        with cls._lock_guard:
            return cls._workspace_locks.setdefault(workspace, threading.Lock())

    @staticmethod
    def _advisory_key(workspace: str) -> int:
        value = int.from_bytes(hashlib.sha256(workspace.encode()).digest()[:8], "big")
        return value & ((1 << 63) - 1)

    def record(self, action: str, *, actor_id: str | None = None, role: str | None = None,
               workspace_id: str | None = None, outcome: str = "SUCCESS",
               details: dict[str, Any] | None = None) -> str:
        context = context_ids()
        ws = workspace_id or context["workspace_id"]
        if not ws:
            raise ValueError("workspace_id is required for audit records")
        safe = scrub(details or {})
        with self._workspace_lock(ws):
            with get_session() as session:
                if session.bind.dialect.name == "postgresql":
                    session.execute(text("SELECT pg_advisory_xact_lock(:key)"),
                                     {"key": self._advisory_key(ws)})
                prev = session.scalar(
                    select(AuditLog).where(AuditLog.workspace_id == ws)
                    .order_by(AuditLog.pk.desc()).limit(1)
                )
                prev_hash = prev.record_hash if prev else ""
                record_id = __import__("uuid").uuid4().hex
                created = datetime.now(timezone.utc)
                canonical = json.dumps({
                    "record_id": record_id, "workspace_id": ws, "actor_id": actor_id,
                    "role": role, "action": action, "outcome": outcome, "details": safe,
                    "request_id": context["request_id"], "event_id": context["event_id"],
                    "incident_id": context["incident_id"], "ai_request_id": context["ai_request_id"],
                    "decision_id": context["decision_id"], "execution_id": context["execution_id"],
                    "created_at": created.isoformat(), "previous_hash": prev_hash,
                }, sort_keys=True, separators=(",", ":"), default=str)
                digest = hashlib.sha256(canonical.encode()).hexdigest()
                row = AuditLog(
                    record_id=record_id, workspace_id=ws, actor_id=actor_id, role=role,
                    action=action, outcome=outcome, details=safe,
                    request_id=context["request_id"], event_id=context["event_id"],
                    incident_id=context["incident_id"], ai_request_id=context["ai_request_id"],
                    decision_id=context["decision_id"], execution_id=context["execution_id"],
                    previous_hash=prev_hash, record_hash=digest, created_at=created,
                )
                session.add(row)
                session.commit()
                return record_id


audit_log = AuditLogger()
