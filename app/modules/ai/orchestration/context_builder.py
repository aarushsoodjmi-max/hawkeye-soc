"""
Evidence/context assembly for the AI layer.

This is the ONLY layer that inspects HawkEye domain data for AI purposes.
Providers never query repositories or the database — evidence always arrives
as an :class:`EvidencePackage` built here. Existing canonical schemas from
``app.schemas`` are reused; nothing is redefined.
"""

from __future__ import annotations

from typing import Any, List, Optional

from app.schemas import AffectedAsset, TimelineEvent

from ..contracts.evidence import (
    BusinessImpact,
    EntityRef,
    EvidencePackage,
    KnowledgeRelation,
    RiskSnapshot,
    SimilarIncident,
    ThreatIntelEnrichment,
)


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _iter(obj: Any) -> List[Any]:
    return list(obj or [])


def _coerce(model: Any, raw: Any) -> Any:
    """Validate raw dicts against the canonical HawkEye schema models."""
    return raw if isinstance(raw, model) else model.model_validate(raw)


class ContextBuilder:
    """Assembles compact, provider-neutral evidence packages.

    ``repository`` and ``memory_service`` are optional injected sources.
    ``build_from_incident`` never touches any repository, which keeps the
    builder fully testable with plain Incident objects.
    """

    def __init__(
        self,
        repository: Any = None,
        memory_service: Any = None,
        max_events: int = 50,
    ) -> None:
        self._repository = repository
        self._memory = memory_service
        self._max_events = max_events

    # ------------------------------------------------------------------
    def build(
        self,
        incident_id: str,
        analyst_notes: Optional[str] = None,
        incident: Any = None,
        workspace_id: Optional[str] = None,
    ) -> EvidencePackage:
        """Build an evidence package for an incident.

        When ``incident`` is omitted, the (injected) repository is used as
        the incident source — never the provider layer.
        """
        if incident is None:
            if self._repository is None:
                raise ValueError(
                    "ContextBuilder has no incident source; pass incident= explicitly"
                )
            incident = self._repository.get_incident_by_id(incident_id, workspace=workspace_id)
            if incident is None:
                raise ValueError(f"incident {incident_id!r} not found")
        return self.build_from_incident(incident, analyst_notes=analyst_notes, workspace_id=workspace_id)

    # ------------------------------------------------------------------
    def build_from_incident(
        self,
        incident: Any,
        analyst_notes: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> EvidencePackage:
        incident_id = str(_get(incident, "id", _get(incident, "incident_id", "")))
        events = [_coerce(TimelineEvent, e) for e in _iter(_get(incident, "timelineEvents"))]
        assets = [_coerce(AffectedAsset, a) for a in _iter(_get(incident, "affectedAssets"))]

        users = self._collect_users(incident)
        entities = [
            EntityRef(
                name=str(_get(a, "name", _get(a, "id", "unknown"))),
                role=str(_get(a, "role", "")),
                risk=str(_get(a, "criticality", "")),
                confidence=1.0,
            )
            for a in assets
            if _get(a, "name") or _get(a, "id")
        ]
        relations = self._collect_relations(incident, events)
        threat_intel = self._collect_threat_intel(incident)

        risk = None
        risk_score = _get(incident, "riskScore")
        if risk_score is not None:
            risk = RiskSnapshot(
                risk_score=int(risk_score),
                risk_level=str(_get(incident, "riskLevel", "") or None),
                breakdown=dict(_get(incident, "riskBreakdown", {}) or {}),
            )

        critical_assets = sum(
            1
            for a in assets
            if str(_get(a, "criticality", "")).upper() in ("TIER 0", "TIER 1")
        )
        canonical_impact = _get(incident, "businessImpact", {}) or {}
        business_impact = BusinessImpact(
            summary=str(canonical_impact.get("summary") or _get(incident, "impactSummary", "")),
            affected_critical_assets=int(canonical_impact.get("critical_asset_count", critical_assets) or critical_assets),
            estimated_downtime_hours=canonical_impact.get("estimated_downtime_hours"),
            financial_estimate_usd=canonical_impact.get("financial_estimate_usd"),
            data_classification=str(canonical_impact.get("data_classification", "estimated")),
        )

        # Cross-module intelligence snapshots. Prefer canonical fields already
        # hydrated on the incident; do not synthesize alternate domain stores.
        prediction = None
        predictions = _iter(_get(incident, "predictions"))
        if predictions:
            prediction = predictions[-1]
        elif _get(incident, "prediction") is not None:
            prediction = _get(incident, "prediction")

        workflow = _get(incident, "workflowIntelligence", _get(incident, "workflowState"))
        confidence = _get(incident, "confidenceContract", _get(incident, "confidenceAssessment"))

        similar = []
        if self._memory is not None and hasattr(self._memory, "similar"):
            if not workspace_id:
                raise ValueError("workspace_id is required when retrieving incident memory")
            for item in self._memory.similar(incident, workspace_id=workspace_id, limit=10)[:10]:
                item_workspace = _get(item, "workspace_id", None)
                if item_workspace != workspace_id:
                    raise ValueError("cross-tenant incident memory detected during evidence assembly")
                similar.append(
                    SimilarIncident(
                        incident_id=str(_get(item, "incident_id", "")),
                        workspace_id=workspace_id,
                        similarity_score=float(_get(item, "similarity_score", 0.0)),
                        root_cause=str(_get(item, "root_cause", "") or None),
                        playbooks_used=list(_get(item, "playbooks_used", []) or []),
                        playbook_successful=bool(_get(item, "playbook_successful", False)),
                    )
                )

        package = EvidencePackage(
            incident_id=incident_id,
            workspace_id=workspace_id,
            incident=incident,
            normalized_events=events,
            affected_assets=assets,
            users=users,
            entities=entities,
            knowledge_graph=relations,
            threat_intelligence=threat_intel,
            risk=risk,
            business_impact=business_impact,
            similar_incidents=similar,
            prediction=prediction if isinstance(prediction, dict) else (prediction.model_dump(mode="json") if hasattr(prediction, "model_dump") else None),
            workflow_intelligence=workflow if isinstance(workflow, dict) else (workflow.model_dump(mode="json") if hasattr(workflow, "model_dump") else None),
            confidence=confidence if isinstance(confidence, dict) else (confidence.model_dump(mode="json") if hasattr(confidence, "model_dump") else None),
            analyst_notes=analyst_notes,
            memory=dict(_get(incident, "incidentMemory", {}) or {}),
        )
        return package.compact(max_events=self._max_events)

    # ------------------------------------------------------------------
    @staticmethod
    def _collect_users(incident: Any) -> List[EntityRef]:
        names: dict[str, EntityRef] = {}
        for alert in _iter(_get(incident, "alerts")):
            user = str(_get(alert, "user", "")).strip()
            if user and user.lower() not in {"system", "unknown", "none"}:
                names.setdefault(user, EntityRef(name=user, role="account"))
        root = _get(incident, "rootCause")
        compromised = str(_get(root, "compromisedAccount", "")).strip() if root else ""
        if compromised and compromised.lower() not in {"unknown", "none", ""}:
            names.setdefault(compromised, EntityRef(name=compromised, role="account", risk="compromised"))
        return list(names.values())

    @staticmethod
    def _collect_relations(incident: Any, events: List[Any]) -> List[KnowledgeRelation]:
        """Read the canonical incident KG when present; fall back to event
        transitions only for incidents that have not yet been hydrated."""
        relations: List[KnowledgeRelation] = []
        canonical = _get(incident, "knowledgeGraph", None)
        if isinstance(canonical, dict) and canonical.get("relationships"):
            for rel in _iter(canonical.get("relationships")):
                source = str(_get(rel, "source", "")).strip()
                target = str(_get(rel, "target", "")).strip()
                if not source or not target:
                    continue
                try:
                    conf = float(_get(rel, "confidence", 0.0) or 0.0)
                except (TypeError, ValueError):
                    conf = 0.0
                relations.append(KnowledgeRelation(
                    source=source,
                    target=target,
                    relationship=str(_get(rel, "relationship_type", _get(rel, "relationship", "observed_transition"))),
                    confidence=max(0.0, min(1.0, conf)),
                    provenance="canonical",
                ))
            return relations
        for event in events:
            source = str(_get(event, "source", "")).strip()
            target = str(_get(event, "target", "")).strip()
            if not source or not target:
                continue
            try:
                conf = float(_get(event, "evidenceConfidence", 0) or 0) / 100.0
            except (TypeError, ValueError):
                conf = 0.0
            relations.append(
                KnowledgeRelation(
                    source=source,
                    target=target,
                    relationship="observed_transition",
                    confidence=max(0.0, min(1.0, conf)),
                    provenance="inferred",
                )
            )
        return relations

    @staticmethod
    def _collect_threat_intel(incident: Any) -> List[ThreatIntelEnrichment]:
        canonical = _get(incident, "threatIntelligence", None)
        if isinstance(canonical, dict):
            indicators = []
            for item in _iter(canonical.get("indicators")):
                if isinstance(item, dict):
                    value = item.get("value")
                else:
                    value = item
                if value:
                    indicators.append(str(value))
            if indicators or canonical.get("threat_actor"):
                return [ThreatIntelEnrichment(
                    source="threat_intelligence",
                    actor=str(canonical.get("threat_actor") or "") or None,
                    indicators=indicators,
                    confidence=float(canonical.get("confidence", 0.0) or 0.0),
                    provenance="canonical",
                )]
        root = _get(incident, "rootCause")
        if root is None:
            return []
        indicators: List[str] = []
        cve = str(_get(root, "cveId", "") or "").strip()
        if cve:
            indicators.append(cve)
        c2 = str(_get(root, "c2Server", "") or "").strip()
        if c2:
            indicators.append(c2)
        if not indicators:
            return []
        return [
            ThreatIntelEnrichment(
                source="incident_root_cause",
                actor=str(_get(incident, "threatActor", "") or None),
                indicators=indicators,
                confidence=float(_get(root, "confidence", 0.0) or 0.0),
            )
        ]
