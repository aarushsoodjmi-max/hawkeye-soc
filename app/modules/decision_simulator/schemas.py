from typing import List
from pydantic import BaseModel, Field
class CascadeAsset(BaseModel):
    asset_id:str; hop_distance:int; decayed_impact:float; reason:str
class RecoveryStep(BaseModel):
    asset_id:str; estimated_start_offset_hours:float; estimated_duration_hours:float
class SimulationResponse(BaseModel):
    incident_id:str; cascade_depth:int
    cascading_affected_assets:List[CascadeAsset]=Field(default_factory=list)
    affected_departments:List[str]=Field(default_factory=list)
    estimated_downtime_hours:float; recovery_time_hours:float; operational_cost:float; confidence_score:float
    recovery_sequence:List[RecoveryStep]=Field(default_factory=list)
