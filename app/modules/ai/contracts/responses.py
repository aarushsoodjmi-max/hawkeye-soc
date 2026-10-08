"""
Strict, typed, provider-neutral AI response contract.

Local and the future Gemini provider must return the exact same structure.
Model output is only accepted after validation against :class:`AiResponse`;
malformed or schema-violating output is rejected and never passed downstream
as trusted data.

Where canonical HawkEye domain schemas already exist (``RootCause``,
``AffectedAsset``, ``RecommendedAction``, ``SeverityType``) they are reused,
not redefined.

Safety invariant: ``requires_user_approval=True`` and ``auto_execute=False``
are enforced by backend validators no matter what the model emits. A model
can never authorize its own execution; proposed playbooks are advisory data
only and execution remains behind HawkEye's existing authorization workflow.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Claim typing: every AI statement is classifiable as an observed fact
# (present in the supplied evidence), an inference (derived by the model),
# or a prediction (forward-looking). Deterministic and provider-neutral.
# ---------------------------------------------------------------------------
ClaimBasis = Literal["observed", "inference", "prediction"]
EvidenceStatus = Literal["sufficient", "insufficient"]

from app.schemas import AffectedAsset, RecommendedAction, RootCause, SeverityType
from .evidence import RiskSnapshot


class SeverityAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore")

    severity: SeverityType
    justification: str = ""
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class AttackPathStep(BaseModel):
    model_config = ConfigDict(extra="ignore")

    order: int = 1
    tactic: str = ""
    technique: str = ""
    techniqueId: str = ""
    source: str = ""
    target: str = ""
    description: str = ""
    confidence: float = Field(0.0, ge=0.0, le=1.0)


class PredictedNextStep(BaseModel):
    model_config = ConfigDict(extra="ignore")

    step: str
    rationale: str = ""
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    timeframe: Optional[str] = None


class AiEvidenceReference(BaseModel):
    """Links an AI claim back to a concrete piece of evidence."""

    model_config = ConfigDict(extra="ignore")

    evidence_id: str
    kind: str = "event"
    summary: str = ""
    source: str = ""
    basis: ClaimBasis = "observed"


class PlaybookStep(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sequence: int = 1
    action_type: str
    target: str = ""
    description: str = ""
    owner_role: Optional[str] = None


class ProposedPlaybook(BaseModel):
    """Advisory playbook proposal. Execution remains behind existing authorization."""

    model_config = ConfigDict(extra="ignore")

    playbook_id: Optional[str] = None
    name: str
    steps: List[PlaybookStep] = Field(default_factory=list)
    based_on: List[str] = Field(default_factory=list)


class AiResponse(BaseModel):
    """
    Canonical structured output of AI analysis.

    Validation is strict (unknown top-level fields are rejected) so malformed
    model output fails safely instead of being passed downstream as trusted
    data.
    """

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    task: str = "analysis"
    generated_at: str = ""
    summary: str
    severity_assessment: Optional[SeverityAssessment] = None
    root_cause: Optional[RootCause] = None  # reused canonical Incident schema
    attack_path: List[AttackPathStep] = Field(default_factory=list)
    affected_assets: List[AffectedAsset] = Field(default_factory=list)  # reused
    predicted_next_steps: List[PredictedNextStep] = Field(default_factory=list)
    predicted_next_action: Optional[PredictedNextStep] = None
    recommendations: List[RecommendedAction] = Field(default_factory=list)  # reused
    risk: Optional[RiskSnapshot] = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    confidence_breakdown: Dict[str, float] = Field(default_factory=dict)
    evidence_references: List[AiEvidenceReference] = Field(default_factory=list)
    proposed_playbook: Optional[ProposedPlaybook] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    simulation_options: List[Dict[str, Any]] = Field(default_factory=list)
    approval_requirement: Dict[str, Any] = Field(default_factory=lambda: {"required": True, "mode": "human", "auto_execute": False})
    # --- explicit answer/reasoning structure (provider-neutral) ----------
    reasoning: str = ""
    # --- post-validation evidence grounding ------------------------------
    evidence_status: EvidenceStatus = "sufficient"
    validation_warnings: List[str] = Field(default_factory=list)
    # --- SAFETY INVARIANT (backend-enforced, model-ignored) --------------
    # The values below are FORCED by validators regardless of what the model
    # outputs: a model can never authorize its own execution.
    requires_user_approval: bool = True
    auto_execute: bool = False

    @field_validator("requires_user_approval", mode="before")
    @classmethod
    def _force_user_approval(cls, _value: Any) -> bool:
        """Safety invariant: user approval is ALWAYS required."""
        return True

    @field_validator("auto_execute", mode="before")
    @classmethod
    def _force_no_auto_execute(cls, _value: Any) -> bool:
        """Safety invariant: a model can never enable auto-execution."""
        return False

    @field_validator("summary")
    @classmethod
    def _summary_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("summary must not be blank")
        return value.strip()

    # ------------------------------------------------------------------
    def with_generated_at(self) -> "AiResponse":
        """Stamp server time when the model omitted ``generated_at``."""
        if self.generated_at:
            return self
        stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return self.model_copy(update={"generated_at": stamp})
