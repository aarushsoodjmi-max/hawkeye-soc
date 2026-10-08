from typing import Optional, List
from pydantic import BaseModel, Field

class PlaybookAction(BaseModel):
    id: str
    action_type: str
    target: str
    status: str = "PENDING"
    executed_at: Optional[str] = None
    executed_by: Optional[str] = None
    result: Optional[str] = None
    description: str = ""
    simulated_at: Optional[str] = None

class ExecutionHistory(BaseModel):
    playbook_id: str
    incident_id: str
    workspace_id: str = "default"
    actions: List[PlaybookAction]
    state: str = "SIMULATED"
    simulation_id: Optional[str] = None
    action_digest: str = ""
    approval: dict = {}
    execution: dict = {}
