"""
HawkEye SOC — Causal Correlation Engine
=========================================
Reconstructs security incidents from noisy, unordered SOC alerts via
entity resolution (user / device / IP) constrained by a temporal window.

Modules
-------
correlation_engine.py : Entity resolution, clustering, confidence scoring.
timeline.py            : Chronological ordering of correlated alerts.
incident_builder.py    : Assembles final structured incident records.

Integration note: this __init__.py was added during backend integration
so that the package's existing relative imports (``from .correlation_engine
import ...``) resolve correctly. No business logic was added or changed.
"""

from .correlation_engine import calculate_confidence, correlate_alerts, group_by_entities
from .timeline import create_attack_timeline, get_first_event, get_last_event
from .incident_builder import assign_incident_ids, build_incident, summarize_incident

__all__ = [
    "calculate_confidence",
    "correlate_alerts",
    "group_by_entities",
    "create_attack_timeline",
    "get_first_event",
    "get_last_event",
    "assign_incident_ids",
    "build_incident",
    "summarize_incident",
]
