"""
executive_summary.py
=====================

Generates short, business-readable executive summaries from analyzed
incidents.

IMPORTANT: This module uses fixed string templates only. It does NOT
call any LLM, external API, or model. All narrative text is produced
via deterministic Python string formatting so output is reproducible
and auditable.

The summary style mirrors what a SOC would hand to non-technical
stakeholders (e.g. CISO, legal, executive leadership): plain language,
no jargon-heavy technique IDs, and a clear recommended next step.
"""

from typing import Any, Dict, List

from . import threat_intelligence as ti

# ---------------------------------------------------------------------------
# Category inference
# ---------------------------------------------------------------------------

# Keywords (lowercased) checked against the incident title/description to
# infer a business-friendly incident category. Order matters: first match wins.
CATEGORY_KEYWORDS: List[tuple] = [
    ("insider_threat", ["insider"]),
    ("credential_dump", ["credential dump", "credential theft", "dumped credentials"]),
    ("phishing_campaign", ["phishing"]),
    ("malware_infection", ["malware", "ransomware", "trojan", "worm"]),
    ("compromised_account", ["compromised account", "account takeover", "compromised employee"]),
]

DEFAULT_CATEGORY = "generic"

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
# Each template receives: attack_chain, root_cause, recommended_action,
# entity_phrase (a short description of affected entities), risk_level.
TEMPLATES: Dict[str, str] = {
    "compromised_account": (
        "Multiple correlated alerts indicate a compromised {entity_phrase}. "
        "The attack progressed through {attack_chain}. "
        "{recommended_action}"
    ),
    "malware_infection": (
        "A malware infection was detected affecting {entity_phrase}. "
        "The infection chain involved {attack_chain}. "
        "{recommended_action}"
    ),
    "phishing_campaign": (
        "A phishing campaign successfully reached {entity_phrase}, leading to {attack_chain}. "
        "{recommended_action}"
    ),
    "insider_threat": (
        "Anomalous activity consistent with insider threat behavior was observed involving "
        "{entity_phrase}, progressing through {attack_chain}. "
        "{recommended_action}"
    ),
    "credential_dump": (
        "Credential theft activity was identified affecting {entity_phrase}, "
        "involving {attack_chain}. "
        "{recommended_action}"
    ),
    "generic": (
        "A security incident ({risk_level} risk) was identified affecting {entity_phrase}. "
        "The activity progressed through {attack_chain}. "
        "{recommended_action}"
    ),
}

# Recommended-action phrasing tuned for an executive audience (shorter,
# outcome-focused, no technical jargon). Keyed by dominant ATT&CK stage.
EXEC_RECOMMENDED_ACTIONS: Dict[str, str] = {
    "Impact": "Immediate containment is underway to limit business disruption.",
    "Exfiltration": "Immediate action is recommended to stop further data loss.",
    "Command and Control": "Network isolation is recommended to cut off attacker access.",
    "Lateral Movement": "Immediate network isolation is recommended to prevent further spread.",
    "Credential Access": "Immediate account suspension and password reset are recommended.",
    "Privilege Escalation": "Immediate account suspension is recommended pending investigation.",
    "Collection": "Access to sensitive data should be restricted while the review continues.",
    "Persistence": "Removal of unauthorized access mechanisms is recommended.",
    "Execution": "The affected endpoint should be quarantined pending analysis.",
    "Initial Access": "A review of perimeter and email security controls is recommended.",
    ti.UNKNOWN_STAGE: "Further investigation is recommended before final remediation steps are taken.",
}


def _infer_category(incident: Dict[str, Any]) -> str:
    """
    Infer a business-friendly incident category from the incident's
    title/description text using simple keyword matching.

    Args:
        incident: The raw incident dict.

    Returns:
        A category key present in TEMPLATES (falls back to "generic").
    """
    haystack = f"{incident.get('title', '')} {incident.get('description', '')}".lower()
    for category, keywords in CATEGORY_KEYWORDS:
        if any(keyword in haystack for keyword in keywords):
            return category
    return DEFAULT_CATEGORY


_ENTITY_KIND_READABLE = {
    "user": "employee account",
    "host": "endpoint",
    "server": "server",
    "cloud": "cloud resource",
    "domain": "domain",
}


def _describe_single_entity(entity: str) -> str:
    """Convert a single 'kind:value' entity identifier into a readable phrase."""
    if ":" in entity:
        kind, value = entity.split(":", 1)
        kind_readable = _ENTITY_KIND_READABLE.get(kind.lower(), kind)
        return f"{kind_readable} {value}"
    return entity


def _entity_phrase(affected_entities: List[str]) -> str:
    """
    Build a short, readable phrase describing affected entities for use
    in a sentence, e.g. "employee account jdoe" or
    "employee account jdoe and endpoint WKS-102" or "3 organizational assets".

    Args:
        affected_entities: List of entity identifiers, e.g. ["user:jdoe"].

    Returns:
        A short natural-language phrase.
    """
    if not affected_entities:
        return "one or more organizational assets"
    if len(affected_entities) == 1:
        return _describe_single_entity(affected_entities[0])
    if len(affected_entities) == 2:
        return " and ".join(_describe_single_entity(e) for e in affected_entities)
    return f"{len(affected_entities)} organizational assets"


def create_executive_summary(incident: Dict[str, Any]) -> str:
    """
    Create a short, business-readable executive summary for an incident.

    This function uses fixed templates only - no LLM calls are made.

    Args:
        incident: Analyzed incident dict (same shape accepted by
            report_generator.generate_incident_report).

    Returns:
        A 2-3 sentence, plain-language executive summary string.
    """
    incident = incident or {}
    events = incident.get("events") or []
    technique_keys = [event.get("technique", "") for event in events]

    attack_chain = ti.get_attack_chain_summary(technique_keys)
    dominant_stage = ti.get_dominant_stage(technique_keys)
    recommended_action = EXEC_RECOMMENDED_ACTIONS.get(
        dominant_stage, EXEC_RECOMMENDED_ACTIONS[ti.UNKNOWN_STAGE]
    )

    category = _infer_category(incident)
    template = TEMPLATES.get(category, TEMPLATES[DEFAULT_CATEGORY])

    # Rough risk level for the generic template (kept simple/independent
    # from report_generator to avoid cross-module coupling on scoring).
    risk_level = "elevated" if dominant_stage in ("Impact", "Exfiltration", "Lateral Movement") else "moderate"

    return template.format(
        attack_chain=attack_chain,
        entity_phrase=_entity_phrase(incident.get("affected_entities") or []),
        recommended_action=recommended_action,
        risk_level=risk_level,
    )
