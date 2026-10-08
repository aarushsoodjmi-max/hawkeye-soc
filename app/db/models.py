from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON


def utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class TenantJSONModel(Base):
    __abstract__ = True
    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    object_id: Mapped[str] = mapped_column(String(512), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class Event(TenantJSONModel):
    __tablename__ = "events"
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="RECEIVED")
    __table_args__ = (UniqueConstraint("workspace_id", "fingerprint", name="uq_events_workspace_fingerprint"), UniqueConstraint("workspace_id", "object_id", name="uq_events_workspace_object"), Index("ix_events_workspace_object", "workspace_id", "object_id"))


class NormalizedEvent(TenantJSONModel):
    __tablename__ = "normalized_events"
    source_event_id: Mapped[str] = mapped_column(String(512), nullable=False)
    __table_args__ = (UniqueConstraint("workspace_id", "source_event_id", name="uq_normalized_workspace_source"),)


class Incident(TenantJSONModel):
    __tablename__ = "incidents"
    __table_args__ = (UniqueConstraint("workspace_id", "object_id", name="uq_incidents_workspace_object"),)


class Asset(TenantJSONModel):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("workspace_id", "object_id", name="uq_assets_workspace_object"),)


class Entity(TenantJSONModel):
    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("workspace_id", "object_id", name="uq_entities_workspace_object"),)


class KnowledgeGraph(TenantJSONModel):
    __tablename__ = "knowledge_graph"


class ThreatIntelligence(TenantJSONModel):
    __tablename__ = "threat_intelligence"


class Risk(TenantJSONModel):
    __tablename__ = "risk"


class Prediction(TenantJSONModel):
    __tablename__ = "prediction"


class Confidence(TenantJSONModel):
    __tablename__ = "confidence"


class IncidentMemory(TenantJSONModel):
    __tablename__ = "incident_memory"


class Decision(TenantJSONModel):
    __tablename__ = "decisions"


class Simulation(TenantJSONModel):
    __tablename__ = "simulations"


class Playbook(TenantJSONModel):
    __tablename__ = "playbooks"


class PlaybookExecution(TenantJSONModel):
    __tablename__ = "playbook_executions"


class EventDispatch(TenantJSONModel):
    """Durable outbox used to make EventBus publication observable/recoverable."""
    __tablename__ = "event_dispatches"
    topic: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="QUEUED")
    __table_args__ = (Index("ix_event_dispatch_workspace_status", "workspace_id", "status"),)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    record_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    workspace_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    incident_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ai_request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    execution_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

