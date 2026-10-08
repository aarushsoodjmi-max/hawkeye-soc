from typing import Any, Dict, List
from pydantic import BaseModel
class NoteRequest(BaseModel): note: str; author_id: str = "analyst"
class MemoryRecord(BaseModel):
    id: str; incident_id: str; summary: str; resolution_status: str; playbooks_used: List[str]; playbook_successful: bool; root_cause: str; signature: Dict[str, Any]; closed_at: str
