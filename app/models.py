"""
Internal domain models for HawkEye SOC.

This file is a placeholder for future internal representations (e.g. ORM
models or in-memory dataclasses) that are distinct from the API-facing
Pydantic schemas in schemas.py.

No business logic or persistence layer is implemented in this skeleton.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class AlertModel:
    """Internal representation of an alert (placeholder)."""

    alert_id: str
    source: str
    severity: str
    description: Optional[str] = None
    host: Optional[str] = None
    timestamp: Optional[datetime] = None


@dataclass
class IncidentModel:
    """Internal representation of an incident (placeholder)."""

    incident_id: str
    title: str
    status: str
    related_alert_ids: List[str] = field(default_factory=list)
    root_cause: Optional[str] = None
    created_at: Optional[datetime] = None
