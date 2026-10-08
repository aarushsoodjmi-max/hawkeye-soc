"""
Provider-neutral AI request contracts.

Both the Local provider and the future Gemini provider consume the same
``AiRequest`` contract. Requests carry only what the AI layer needs; all
domain context arrives through the ``EvidencePackage``
(see :mod:`app.modules.ai.contracts.evidence`).
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

AiTask = Literal[
    "analysis",
    "incident_assessment",
    "root_cause_analysis",
    "next_steps_prediction",
    "recommendations",
    "playbook_proposal",
    "general",
]


class AiRequestOptions(BaseModel):
    """Optional per-request generation overrides. None keeps configured defaults."""

    model_config = ConfigDict(extra="forbid")

    model: Optional[str] = Field(None, description="Explicit model override")
    temperature: Optional[float] = Field(None, ge=0.0, le=2.0)
    max_tokens: Optional[int] = Field(None, gt=0)


class AiRequest(BaseModel):
    """Common AI request accepted by any AIProvider implementation."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    # Trusted tenant context propagated from the authenticated boundary.
    workspace_id: Optional[str] = None
    task: AiTask = "analysis"
    analyst_instructions: Optional[str] = Field(
        None, description="Optional analyst guidance appended to the prompt"
    )
    options: Optional[AiRequestOptions] = None


class AiAnalyzeRequest(BaseModel):
    """HTTP contract for the orchestrator integration route (/api/ai/analyze)."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str
    task: AiTask = "analysis"
    analyst_instructions: Optional[str] = None
    options: Optional[AiRequestOptions] = None
    provider: str = "local"
