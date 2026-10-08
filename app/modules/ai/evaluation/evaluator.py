"""
Evaluation of structured AI responses.

Evaluates a validated :class:`AiResponse` for section completeness and
internal consistency. Evaluations feed future training/evaluation pipelines
(model registry gating) without being coupled to runtime inference.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts.evidence import EvidencePackage
from ..contracts.responses import AiResponse


@dataclass
class EvaluationReport:
    valid: bool
    score: float
    checks: Dict[str, bool]
    issues: List[str] = field(default_factory=list)


def evaluate_response(
    response: AiResponse,
    evidence: Optional[EvidencePackage] = None,
) -> EvaluationReport:
    """Score a response for completeness/consistency. 1.0 = fully formed."""
    issues: List[str] = []
    checks: Dict[str, bool] = {
        "summary_present": bool(response.summary.strip()),
        "confidence_in_range": 0.0 <= response.confidence <= 1.0,
        "has_root_cause": response.root_cause is not None,
        "has_recommendations": len(response.recommendations) > 0,
        "has_predicted_steps": len(response.predicted_next_steps) > 0,
        "has_evidence_references": len(response.evidence_references) > 0,
    }
    if response.severity_assessment is not None:
        checks["severity_conf_in_range"] = (
            0.0 <= response.severity_assessment.confidence <= 1.0
        )
    else:
        checks["severity_conf_in_range"] = False
        issues.append("severity_assessment missing")

    if evidence is not None:
        known_events = {e.id for e in evidence.normalized_events}
        dangling = [
            r.evidence_id
            for r in response.evidence_references
            if r.kind == "event" and r.evidence_id not in known_events
        ]
        checks["evidence_references_resolve"] = not dangling
        if dangling:
            issues.append(f"evidence references do not resolve: {dangling[:5]}")

    for key, ok in checks.items():
        if not ok:
            issues.append(f"check failed: {key}")

    score = sum(1 for ok in checks.values() if ok) / max(1, len(checks))
    return EvaluationReport(
        valid=bool(checks.get("summary_present") and checks.get("confidence_in_range")),
        score=round(score, 4),
        checks=checks,
        issues=issues,
    )
