from __future__ import annotations
from copy import deepcopy
from typing import Any, Type
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError
from .models import (
    Base, Event, NormalizedEvent, Incident, Asset, Entity, KnowledgeGraph,
    ThreatIntelligence, Risk, Prediction, Confidence, IncidentMemory,
    Decision, Simulation, Playbook, PlaybookExecution, EventDispatch, AuditLog,
)
from .session import get_session, init_db

MODEL_MAP = {
    "events": Event,
    "normalized_events": NormalizedEvent,
    "incidents": Incident,
    "assets": Asset,
    "entities": Entity,
    "knowledge_graph": KnowledgeGraph,
    "threat_intelligence": ThreatIntelligence,
    "risk": Risk,
    "prediction": Prediction,
    "confidence": Confidence,
    "incident_memory": IncidentMemory,
    "decisions": Decision,
    "simulations": Simulation,
    "playbooks": Playbook,
    "playbook_executions": PlaybookExecution,
    "event_dispatches": EventDispatch,
}


class PersistentStateRepository:
    """Small tenant-aware persistence adapter used by existing services.

    Domain contracts remain Pydantic/service-facing; persistence stores JSON
    snapshots with explicit tenant keys. This keeps the existing architecture
    intact while making state durable and restart-safe.
    """
    def __init__(self):
        init_db()

    def model(self, kind: str) -> Type[Any]:
        try:
            return MODEL_MAP[kind]
        except KeyError as exc:
            raise ValueError(f"unknown persistence kind: {kind}") from exc

    def upsert(self, kind: str, workspace_id: str, object_id: str, payload: dict, **fields: Any):
        if not workspace_id:
            raise ValueError("workspace_id is required")
        model = self.model(kind)
        with get_session() as session:
            stmt = select(model).where(model.workspace_id == workspace_id, model.object_id == str(object_id))
            row = session.scalar(stmt)
            if row is None:
                values = dict(workspace_id=workspace_id, object_id=str(object_id), payload=deepcopy(payload), **fields)
                row = model(**values)
                session.add(row)
            else:
                row.payload = deepcopy(payload)
                for key, value in fields.items():
                    if hasattr(row, key):
                        setattr(row, key, value)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                row = session.scalar(stmt)
                if row is None:
                    raise
                row.payload = deepcopy(payload)
                session.commit()
            return deepcopy(row.payload)

    def insert_event(self, workspace_id: str, event_id: str, payload: dict, fingerprint: str) -> bool:
        with get_session() as session:
            row = Event(workspace_id=workspace_id, object_id=event_id, payload=deepcopy(payload), fingerprint=fingerprint, status="RECEIVED")
            session.add(row)
            try:
                session.commit()
                return True
            except IntegrityError:
                session.rollback()
                return False

    def event_exists(self, workspace_id: str, fingerprint: str) -> bool:
        with get_session() as session:
            return session.scalar(select(Event.pk).where(Event.workspace_id == workspace_id, Event.fingerprint == fingerprint)) is not None

    def upsert_normalized_event(self, workspace_id: str, event_id: str, payload: dict):
        return self.upsert("normalized_events", workspace_id, event_id, payload, source_event_id=event_id)

    def update_event(self, workspace_id: str, event_id: str, payload: dict) -> None:
        model = Event
        with get_session() as session:
            row = session.scalar(select(model).where(model.workspace_id == workspace_id, model.object_id == str(event_id)))
            if row:
                row.payload = deepcopy(payload)
                row.status = "PROCESSED"
                session.commit()

    def get(self, kind: str, workspace_id: str, object_id: str) -> dict | None:
        if not workspace_id:
            raise ValueError("workspace_id is required")
        model = self.model(kind)
        with get_session() as session:
            row = session.scalar(select(model).where(model.workspace_id == workspace_id, model.object_id == str(object_id)))
            return deepcopy(row.payload) if row else None

    def list_all(self, kind: str, limit: int = 100000) -> list[tuple[str, str, dict]]:
        model = self.model(kind)
        with get_session() as session:
            rows = session.scalars(select(model).order_by(model.pk.asc()).limit(limit)).all()
            return [(r.workspace_id, r.object_id, deepcopy(r.payload)) for r in rows]

    def list(self, kind: str, workspace_id: str, limit: int = 1000) -> list[dict]:
        if not workspace_id:
            raise ValueError("workspace_id is required")
        model = self.model(kind)
        with get_session() as session:
            rows = session.scalars(select(model).where(model.workspace_id == workspace_id).order_by(model.pk.desc()).limit(limit)).all()
            return [deepcopy(r.payload) for r in rows]

    def delete(self, kind: str, workspace_id: str, object_id: str) -> bool:
        model = self.model(kind)
        with get_session() as session:
            row = session.scalar(select(model).where(model.workspace_id == workspace_id, model.object_id == str(object_id)))
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    def delete_workspace(self, kind: str, workspace_id: str) -> None:
        model = self.model(kind)
        with get_session() as session:
            session.execute(delete(model).where(model.workspace_id == workspace_id))
            session.commit()

    def queue_dispatch(self, workspace_id: str, event_id: str, topic: str, payload: dict):
        return self.upsert("event_dispatches", workspace_id, event_id, payload, topic=topic, status="QUEUED")

    def mark_dispatch(self, workspace_id: str, event_id: str, status: str):
        model = EventDispatch
        with get_session() as session:
            row = session.scalar(select(model).where(model.workspace_id == workspace_id, model.object_id == event_id))
            if row:
                row.status = status
                session.commit()

    def queued_dispatches(self, limit: int = 10000):
        model = EventDispatch
        with get_session() as session:
            rows = session.scalars(select(model).where(model.status == "QUEUED").order_by(model.pk.asc()).limit(limit)).all()
            return [(r.workspace_id, r.object_id, r.topic, deepcopy(r.payload)) for r in rows]


def list_audit_logs(workspace_id: str, limit: int = 100) -> list[dict[str, Any]]:
    if not workspace_id:
        raise ValueError("workspace_id is required")
    with get_session() as session:
        rows = session.scalars(
            select(AuditLog)
            .where(AuditLog.workspace_id == workspace_id)
            .order_by(AuditLog.pk.desc())
            .limit(limit)
        ).all()
        return [
            {
                "id": row.record_id,
                "timestamp": row.created_at.isoformat(),
                "action": row.action,
                "actorId": row.actor_id or "",
                "role": row.role or "",
                "workspaceId": row.workspace_id,
                "outcome": row.outcome,
                "details": row.details,
            }
            for row in rows
        ]

class EventRepository(PersistentStateRepository):
    kind = "events"
class NormalizedEventRepository(PersistentStateRepository):
    kind = "normalized_events"
class IncidentRepository(PersistentStateRepository):
    kind = "incidents"
class AssetRepository(PersistentStateRepository):
    kind = "assets"
class EntityRepository(PersistentStateRepository):
    kind = "entities"
class KnowledgeGraphRepository(PersistentStateRepository):
    kind = "knowledge_graph"
class ThreatIntelligenceRepository(PersistentStateRepository):
    kind = "threat_intelligence"
class RiskRepository(PersistentStateRepository):
    kind = "risk"
class PredictionRepository(PersistentStateRepository):
    kind = "prediction"
class ConfidenceRepository(PersistentStateRepository):
    kind = "confidence"
class IncidentMemoryRepository(PersistentStateRepository):
    kind = "incident_memory"
class DecisionRepository(PersistentStateRepository):
    kind = "decisions"
class SimulationRepository(PersistentStateRepository):
    kind = "simulations"
class PlaybookRepository(PersistentStateRepository):
    kind = "playbooks"
class PlaybookExecutionRepository(PersistentStateRepository):
    kind = "playbook_executions"


class AuditLogRepository(PersistentStateRepository):
    """Read-only access helper; audit rows are append-only through AuditLogger."""
    def list(self, kind: str, workspace_id: str, limit: int = 1000):
        raise RuntimeError("Audit logs are not mutable through generic repository")
