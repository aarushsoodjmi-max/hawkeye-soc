from typing import List
from pydantic import BaseModel,Field
class Strategy(BaseModel):
    id:str; name:str; description:str; actions:List[str]=Field(default_factory=list); risk_reduction:int; downtime_hours:float; recovery_time_hours:float; operational_cost:float; confidence:float; rationale:List[str]=Field(default_factory=list)
class StrategyResponse(BaseModel): incident_id:str; strategies:List[Strategy]; generated_at:str
