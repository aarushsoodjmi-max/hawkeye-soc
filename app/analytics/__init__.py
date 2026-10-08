"""
HawkEye SOC - Analytics & Explainability module.

This package turns *correlated incidents* (the output of an upstream
correlation engine) into SOC intelligence:

    - metrics.py          -> quantitative SOC metrics (compression, MTTR, etc.)
    - explainability.py   -> human-readable, template-based incident narratives
    - risk_scoring.py     -> weighted 0-100 incident risk scoring

Nothing in this package builds APIs, servers, or UI. It is a pure-Python
(+ pandas) analytics layer that other modules can import and call directly:

    from backend.app.analytics import metrics, explainability, risk_scoring

    stats   = metrics.incident_statistics(incidents)
    story   = explainability.explain_incident(incident)
    scoring = risk_scoring.calculate_risk_score(incident)
"""

from . import metrics, explainability, risk_scoring

__all__ = ["metrics", "explainability", "risk_scoring"]
