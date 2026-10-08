from typing import Any, Dict, List
from pydantic import BaseModel
class PredictedAsset(BaseModel): asset: str; reason: str; confidence: float
class PredictionResponse(BaseModel):
    incident_id: str
    generated_at: str
    next_affected_assets: List[PredictedAsset]
    lateral_movement: Dict[str, Any]
    downtime: Dict[str, Any]
    affected_users: Dict[str, Any]
    overall_confidence: float
