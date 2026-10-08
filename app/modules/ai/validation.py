"""
Deterministic post-inference evidence grounding for the HawkEye AI layer.

Validation has two gates:
1. references must resolve to evidence supplied in the package;
2. claim summaries must be grounded in the referenced evidence content.

This is deliberately a practical MVP validator, not a semantic theorem prover.
It is provider-neutral and fail-closed for unsupported observed claims.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Set

from .contracts.evidence import EvidencePackage
from .contracts.responses import AiResponse
from .errors import AiError

logger = logging.getLogger("hawkeye.ai.validation")

INSUFFICIENT_EVIDENCE_CONFIDENCE_CAP = 0.3
_INSUFFICIENT_MARKERS = {"insufficient", "insufficient_evidence", "insufficient-evidence"}
_STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "was", "were", "has",
    "have", "into", "onto", "via", "observed", "evidence", "event", "claim",
    "analysis", "based", "only", "then", "than", "its", "their", "there",
}


class EvidenceGroundingError(AiError):
    """AI output cites missing, unrelated, or misclassified evidence."""

    def __init__(self, message: str, *, details: Dict[str, Any] | None = None):
        super().__init__(message, code="evidence_grounding_failed", details=details)


def _incident_marker(incident_id: str) -> str:
    return f"incident:{incident_id}"


def build_evidence_index(evidence: EvidencePackage) -> Set[str]:
    ids: Set[str] = {evidence.incident_id, _incident_marker(evidence.incident_id)}
    for event in evidence.normalized_events:
        if event.id:
            ids.add(event.id)
    for asset in evidence.affected_assets:
        if asset.id:
            ids.add(asset.id)
        if asset.name:
            ids.add(asset.name)
    for user in evidence.users:
        if user.name:
            ids.add(user.name)
    for entity in evidence.entities:
        if entity.name:
            ids.add(entity.name)
    for relation in evidence.knowledge_graph:
        if relation.source and relation.target:
            ids.update({f"{relation.source}->{relation.target}", relation.source, relation.target})
    for intel in evidence.threat_intelligence:
        if intel.source:
            ids.add(intel.source)
        ids.update(i for i in intel.indicators if i)
    for similar in evidence.similar_incidents:
        if similar.incident_id:
            ids.add(similar.incident_id)
    if evidence.memory:
        ids.add("incident_memory")
    if evidence.analyst_notes:
        ids.add("analyst_notes")
    for name, value in (
        ("risk", evidence.risk),
        ("business_impact", evidence.business_impact),
        ("prediction", evidence.prediction),
        ("workflow_intelligence", evidence.workflow_intelligence),
        ("confidence", evidence.confidence),
    ):
        if value is not None:
            ids.add(name)
    return ids


def _resolved_kinds(reference_id: str, evidence: EvidencePackage, index: Set[str]) -> Set[str]:
    kinds: Set[str] = set()
    if reference_id in {e.id for e in evidence.normalized_events}:
        kinds.add("event")
    if reference_id in {a.id for a in evidence.affected_assets} or reference_id in {a.name for a in evidence.affected_assets}:
        kinds.add("asset")
    if reference_id in {u.name for u in evidence.users} or reference_id in {e.name for e in evidence.entities}:
        kinds.add("entity")
    if reference_id in {s.incident_id for s in evidence.similar_incidents}:
        kinds.add("incident_memory")
    if reference_id == "incident_memory" and evidence.memory:
        kinds.add("incident_memory")
    if reference_id in {t.source for t in evidence.threat_intelligence} or any(reference_id in t.indicators for t in evidence.threat_intelligence):
        kinds.add("threat_intelligence")
    if any(reference_id == f"{r.source}->{r.target}" or reference_id in (r.source, r.target) for r in evidence.knowledge_graph):
        kinds.add("knowledge_graph")
    if reference_id == "risk" and evidence.risk is not None:
        kinds.add("risk")
    if reference_id == "business_impact" and evidence.business_impact is not None:
        kinds.add("business_impact")
    if reference_id == "prediction" and evidence.prediction is not None:
        kinds.add("prediction")
    if reference_id == "workflow_intelligence" and evidence.workflow_intelligence is not None:
        kinds.add("workflow_intelligence")
    if reference_id == "confidence" and evidence.confidence is not None:
        kinds.add("confidence")
    if reference_id == "analyst_notes" and evidence.analyst_notes:
        kinds.add("analyst_notes")
    if reference_id in (evidence.incident_id, _incident_marker(evidence.incident_id)):
        kinds.add("incident")
    return kinds


def _evidence_is_empty(evidence: EvidencePackage) -> bool:
    return (
        evidence.incident is None
        and not evidence.normalized_events
        and not evidence.affected_assets
        and not evidence.users
        and not evidence.entities
        and not evidence.knowledge_graph
        and not evidence.threat_intelligence
        and evidence.risk is None
        and evidence.business_impact is None
        and evidence.prediction is None
        and evidence.workflow_intelligence is None
        and evidence.confidence is None
        and not evidence.similar_incidents
        and not evidence.memory
        and not (evidence.analyst_notes or "").strip()
    )


def _tokens(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[A-Za-z0-9_.:/-]{3,}", value.lower())
        if token not in _STOPWORDS
    }


def _reference_content(reference_id: str, evidence: EvidencePackage) -> str:
    chunks: list[str] = []
    for event in evidence.normalized_events:
        if event.id == reference_id:
            chunks.extend([
                event.id, event.title, event.description, event.source, event.target,
                event.technique, event.techniqueId, event.command or "",
                str(event.ioc or ""),
            ])
    for asset in evidence.affected_assets:
        if reference_id in {asset.id, asset.name}:
            chunks.extend([asset.id, asset.name, asset.ip, asset.os, asset.role, asset.status, asset.criticality])
    for obj in (*evidence.users, *evidence.entities):
        if obj.name == reference_id:
            chunks.extend([obj.name, obj.role or "", obj.risk or ""])
    for rel in evidence.knowledge_graph:
        if reference_id in {rel.source, rel.target, f"{rel.source}->{rel.target}"}:
            chunks.extend([rel.source, rel.target, rel.relationship])
    for intel in evidence.threat_intelligence:
        if reference_id == intel.source or reference_id in intel.indicators:
            chunks.extend([intel.source, intel.actor or "", *intel.indicators])
    for similar in evidence.similar_incidents:
        if similar.incident_id == reference_id:
            chunks.extend([similar.incident_id, similar.root_cause or "", *similar.playbooks_used])
    if reference_id == "risk" and evidence.risk:
        chunks.append(str(evidence.risk.model_dump(mode="json")))
    if reference_id == "business_impact" and evidence.business_impact:
        chunks.append(str(evidence.business_impact.model_dump(mode="json")))
    if reference_id == "prediction" and evidence.prediction:
        chunks.append(str(evidence.prediction))
    if reference_id == "workflow_intelligence" and evidence.workflow_intelligence:
        chunks.append(str(evidence.workflow_intelligence))
    if reference_id == "confidence" and evidence.confidence:
        chunks.append(str(evidence.confidence))
    if reference_id == "incident_memory" and evidence.memory:
        chunks.append(str(evidence.memory))
    if reference_id == "analyst_notes" and evidence.analyst_notes:
        chunks.append(evidence.analyst_notes)
    if reference_id in {evidence.incident_id, _incident_marker(evidence.incident_id)}:
        chunks.append(str(evidence.context_sections().get("incident")))
    return " ".join(chunks)


def _is_simulated_kind(kind: str) -> bool:
    return kind.strip().lower() in {"simulation", "simulated", "decision_simulation", "digital_twin"}


def validate_response(
    response: AiResponse,
    evidence: EvidencePackage,
    *,
    model_declared_insufficient: bool = False,
) -> AiResponse:
    warnings: List[str] = []
    index = build_evidence_index(evidence)
    resolved_any = False

    # AI may summarize affected assets but may not manufacture new asset
    # identities. Bind every returned asset to the canonical evidence package.
    canonical_assets = {str(a.id): a for a in evidence.affected_assets}
    canonical_asset_names = {str(a.name): a for a in evidence.affected_assets}
    for asset in response.affected_assets:
        if str(asset.id) not in canonical_assets and str(asset.name) not in canonical_asset_names:
            raise EvidenceGroundingError(
                f"AI affected asset {asset.id!r} is not present in supplied evidence",
                details={"asset_id": asset.id, "asset_name": asset.name},
            )

    for ref in response.evidence_references:
        kinds = _resolved_kinds(ref.evidence_id, evidence, index)
        if not kinds:
            raise EvidenceGroundingError(
                f"Evidence reference {ref.evidence_id!r} does not exist in the supplied evidence",
                details={"evidence_id": ref.evidence_id},
            )
        resolved_any = True

        declared_kind = ref.kind.strip().lower()
        if declared_kind not in {"", *{k.lower() for k in kinds}}:
            raise EvidenceGroundingError(
                f"Evidence reference {ref.evidence_id!r} declares unrelated kind {ref.kind!r}",
                details={"evidence_id": ref.evidence_id, "declared_kind": ref.kind, "actual_kinds": sorted(kinds)},
            )
        if "confidence" in kinds:
            raise EvidenceGroundingError(
                f"Confidence cannot be used as evidence for claim {ref.evidence_id!r}",
                details={"evidence_id": ref.evidence_id},
            )
        if ref.basis == "observed" and (
            "prediction" in kinds or _is_simulated_kind(declared_kind)
        ):
            raise EvidenceGroundingError(
                f"Observed claim {ref.evidence_id!r} is grounded in non-observed evidence",
                details={"evidence_id": ref.evidence_id, "actual_kinds": sorted(kinds)},
            )

        content = _reference_content(ref.evidence_id, evidence)
        claim_tokens = _tokens(ref.summary)
        evidence_tokens = _tokens(content)
        if not claim_tokens:
            raise EvidenceGroundingError(
                f"{ref.basis.title()} claim {ref.evidence_id!r} has no groundable summary",
                details={"evidence_id": ref.evidence_id},
            )
        if not (claim_tokens & evidence_tokens):
            raise EvidenceGroundingError(
                f"{ref.basis.title()} claim {ref.evidence_id!r} is not grounded in the referenced evidence",
                details={"evidence_id": ref.evidence_id},
            )

        if ref.basis == "prediction":
            continue
        if kinds & {"event", "asset", "knowledge_graph", "incident", "threat_intelligence"}:
            ref.basis = "observed"

    insufficient = model_declared_insufficient
    if _evidence_is_empty(evidence):
        insufficient = True
        if not response.evidence_references:
            warnings.append("insufficient evidence: the evidence package contains no substantive evidence for this analysis")
    if response.evidence_references and not resolved_any:
        insufficient = True

    confidence = response.confidence
    if insufficient and confidence > INSUFFICIENT_EVIDENCE_CONFIDENCE_CAP:
        warnings.append(f"confidence capped to {INSUFFICIENT_EVIDENCE_CONFIDENCE_CAP} because evidence is insufficient")
        confidence = INSUFFICIENT_EVIDENCE_CONFIDENCE_CAP

    update = {
        "validation_warnings": warnings,
        "evidence_status": "insufficient" if insufficient else "sufficient",
    }
    if confidence != response.confidence:
        update["confidence"] = confidence

    validated = response.model_copy(update=update)
    logger.info(
        "ai response validated incident=%s status=%s warnings=%d",
        response.incident_id,
        update["evidence_status"],
        len(warnings),
    )
    return validated


def model_declared_insufficient_evidence(raw: dict) -> bool:
    for key in ("status", "evidence_status", "evidenceStatus"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip().lower() in _INSUFFICIENT_MARKERS:
            return True
    return False
