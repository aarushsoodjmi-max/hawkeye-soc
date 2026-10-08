"""
Structured, compact, provider-neutral evidence package.

The orchestration/context layer assembles an ``EvidencePackage`` from
existing HawkEye domain objects (reusing the canonical schemas in
``app/schemas.py``) and hands it to the AI provider. The provider NEVER
queries repositories or the database: evidence always arrives through this
contract. Uncontrolled raw data is never dumped into the model — large
collections are pruned by :meth:`EvidencePackage.compact`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from app.schemas import AffectedAsset, Incident, TimelineEvent


class EntityRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    role: Optional[str] = None
    risk: Optional[str] = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class KnowledgeRelation(BaseModel):
    """Minimal knowledge-graph edge (entity/event level, provider-neutral)."""

    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    relationship: str = "observed_transition"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    provenance: str = "canonical"


class ThreatIntelEnrichment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    actor: Optional[str] = None
    indicators: List[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    provenance: str = "canonical"


class RiskSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: Optional[int] = Field(None, ge=0, le=100)
    risk_level: Optional[str] = None
    breakdown: Dict[str, Any] = Field(default_factory=dict)


class BusinessImpact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: Optional[str] = None
    affected_critical_assets: int = 0
    estimated_downtime_hours: Optional[float] = None
    financial_estimate_usd: Optional[float] = None
    data_classification: str = "estimated"


class SimilarIncident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    workspace_id: Optional[str] = None
    similarity_score: float = Field(0.0, ge=0.0, le=1.0)
    root_cause: Optional[str] = None
    playbooks_used: List[str] = Field(default_factory=list)
    playbook_successful: bool = False


class EvidencePackage(BaseModel):
    """Compact, serializable context handed to the AI layer.

    ``normalized_events``, ``affected_assets`` and ``incident`` reuse the
    canonical HawkEye schemas (``TimelineEvent``, ``AffectedAsset``,
    ``Incident``) — they are NOT redefined here.
    """

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    # Set by the authenticated orchestration boundary. Optional only for
    # provider-unit compatibility; HTTP AI requests must provide it.
    workspace_id: Optional[str] = None
    incident: Optional[Union[Incident, Dict[str, Any]]] = None
    normalized_events: List[TimelineEvent] = Field(default_factory=list)
    affected_assets: List[AffectedAsset] = Field(default_factory=list)
    users: List[EntityRef] = Field(default_factory=list)
    entities: List[EntityRef] = Field(default_factory=list)
    knowledge_graph: List[KnowledgeRelation] = Field(default_factory=list)
    threat_intelligence: List[ThreatIntelEnrichment] = Field(default_factory=list)
    risk: Optional[RiskSnapshot] = None
    business_impact: Optional[BusinessImpact] = None
    similar_incidents: List[SimilarIncident] = Field(default_factory=list)
    memory: Dict[str, Any] = Field(default_factory=dict)
    # Cross-module intelligence explicitly supplied to the AI. These are
    # snapshots, not alternate sources of truth.
    prediction: Optional[Dict[str, Any]] = None
    workflow_intelligence: Optional[Dict[str, Any]] = None
    confidence: Optional[Dict[str, Any]] = None
    analyst_notes: Optional[str] = None


    def assert_workspace(self, workspace_id: str) -> "EvidencePackage":
        """Enforce the final tenant invariant before AI consumption."""
        if not isinstance(workspace_id, str) or not workspace_id.strip():
            raise ValueError("workspace_id is required for AI evidence")
        if self.workspace_id != workspace_id:
            raise ValueError("EvidencePackage workspace does not match authenticated workspace")
        for item in self.similar_incidents:
            if item.workspace_id != workspace_id:
                raise ValueError("EvidencePackage contains cross-tenant incident memory")
        if self.memory:
            memory_workspace = self.memory.get("workspace_id") if isinstance(self.memory, dict) else None
            if memory_workspace is not None and str(memory_workspace) != workspace_id:
                raise ValueError("EvidencePackage memory workspace mismatch")
            for note in self.memory.get("notes", []) if isinstance(self.memory, dict) else []:
                if isinstance(note, dict) and note.get("workspace_id") and str(note["workspace_id"]) != workspace_id:
                    raise ValueError("EvidencePackage contains cross-tenant memory note")
        # Domain incident/events/assets are assembled from one repository
        # incident already resolved under the authenticated workspace. If a
        # caller supplied explicit workspace metadata, it must agree too.
        if self.incident is not None:
            metadata = self.incident.get("metadata", {}) if isinstance(self.incident, dict) else getattr(self.incident, "metadata", {})
            if isinstance(metadata, dict) and metadata.get("workspace") and str(metadata["workspace"]) != workspace_id:
                raise ValueError("EvidencePackage incident workspace mismatch")
        return self

    # ------------------------------------------------------------------
    def compact(
        self,
        max_events: int = 50,
        max_assets: int = 100,
        max_relations: int = 200,
    ) -> "EvidencePackage":
        """Prune large collections so raw data is never dumped uncontrolled into the model."""
        copy = self.model_copy(deep=True)
        copy.normalized_events = copy.normalized_events[:max_events]
        copy.affected_assets = copy.affected_assets[:max_assets]
        copy.entities = copy.entities[:max_assets]
        copy.users = copy.users[:max_assets]
        copy.knowledge_graph = copy.knowledge_graph[:max_relations]
        copy.threat_intelligence = copy.threat_intelligence[:max_assets]
        copy.similar_incidents = copy.similar_incidents[:10]
        if copy.memory:
            copy.memory = dict(copy.memory)
            if isinstance(copy.memory.get("notes"), list):
                copy.memory["notes"] = copy.memory["notes"][:20]
        return copy

    # ------------------------------------------------------------------
    def context_sections(self) -> Dict[str, Any]:
        """Compact, prompt-ready sections (no raw log blobs)."""
        incident_summary = None
        if self.incident is not None:
            inc = self.incident

            def g(key: str, default: Any = None) -> Any:
                return inc.get(key, default) if isinstance(inc, dict) else getattr(inc, key, default)

            incident_summary = {
                "id": g("id"),
                "title": g("title"),
                "severity": g("severity"),
                "status": g("status"),
                "threat_actor": g("threatActor"),
                "impact_summary": g("impactSummary"),
            }
        return {
            "incident": incident_summary,
            "normalized_events": [e.model_dump(mode="json") for e in self.normalized_events],
            "affected_assets": [a.model_dump(mode="json") for a in self.affected_assets],
            "users": [u.model_dump(mode="json") for u in self.users],
            "entities": [e.model_dump(mode="json") for e in self.entities],
            "knowledge_graph": [r.model_dump(mode="json") for r in self.knowledge_graph],
            "threat_intelligence": [t.model_dump(mode="json") for t in self.threat_intelligence],
            "risk": self.risk.model_dump(mode="json") if self.risk else None,
            "business_impact": self.business_impact.model_dump(mode="json") if self.business_impact else None,
            "similar_incidents": [s.model_dump(mode="json") for s in self.similar_incidents],
            "incident_memory": self.memory,
            "prediction": self.prediction,
            "workflow_intelligence": self.workflow_intelligence,
            "confidence": self.confidence,
            "analyst_notes": self.analyst_notes,
        }
