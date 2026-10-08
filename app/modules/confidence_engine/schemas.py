from typing import Any, Dict
from pydantic import BaseModel
class ConfidenceResponse(BaseModel):
    subject_type: str; subject_id: str
    correlation_confidence: float; ml_confidence: float; threat_intel_confidence: float
    data_quality_score: float; evidence_completeness_score: float
    unified_confidence: float; unified_confidence_percent: float
    confidence_partial: bool; weights: Dict[str, float]; breakdown: Dict[str, Any]; computed_at: str
