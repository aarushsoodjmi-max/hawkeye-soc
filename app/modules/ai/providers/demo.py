"""Deterministic AI provider used only in DEMO_MODE."""
from __future__ import annotations

from app.modules.ai.contracts.responses import AiResponse
from app.modules.ai.providers.base import AIProvider
from app.modules.decision_engine.service import generate_strategies

class DeterministicDemoProvider(AIProvider):
    """Provider-neutral, side-effect-free AI adapter for offline demos only."""
    name = "demo"

    def models(self):
        return [{"model_name": "hawkeye-deterministic-demo", "provider": self.name, "remote": False}]

    def health(self):
        return {"provider": self.name, "status": "ok", "configured": True, "reachable": True, "model": "hawkeye-deterministic-demo"}

    def analyze(self, request, evidence):
        events = evidence.normalized_events
        refs = []
        for event in events:
            refs.append({"evidence_id": getattr(event, "id", ""), "kind": "event", "summary": getattr(event, "title", ""), "source": getattr(event, "source", ""), "basis": "observed"})
        assets = [a.model_dump(mode="json") for a in evidence.affected_assets]
        attack_path = []
        for order, event in enumerate(events, 1):
            attack_path.append({"order": order, "tactic": getattr(event, "tactic", ""), "technique": getattr(event, "technique", ""), "techniqueId": getattr(event, "techniqueId", ""), "source": getattr(event, "source", ""), "target": getattr(event, "target", ""), "description": getattr(event, "description", ""), "confidence": 0.96})
        root = {
            "vector": "Credential compromise followed by remote access",
            "entryPoint": "Compromised account",
            "compromisedAccount": "alex.morgan",
            "c2Server": "",
            "c2Location": "",
            "vulnerabilityDetails": "Deterministic demo evidence only",
            "detectionMechanism": "Hawkeye correlation",
            "initialPayload": "Credential compromise",
            "firstObserved": getattr(events[0], "timestamp", "") if events else "",
            "primary": "credential_compromise",
            "confidence": 0.96,
            "reasoning": "Observed credential compromise, impossible travel, VPN, PowerShell, credential access, lateral movement and privileged access form a coherent attack chain.",
            "contributingFactors": ["Compromised credential", "Remote access", "Privileged account use"],
        }
        actions = [s.actions[0] for s in generate_strategies(evidence.incident)] if evidence.incident else ["Isolate Device"]
        return AiResponse.model_validate({
            "incident_id": request.incident_id,
            "task": request.task,
            "summary": "Deterministic demo investigation identified a credential compromise progressing through remote access to a critical server.",
            "reasoning": root["reasoning"],
            "root_cause": root,
            "attack_path": attack_path,
            "affected_assets": assets,
            "predicted_next_steps": [{"step": "Contain the finance workstation", "rationale": "Observed lateral movement toward a critical server", "confidence": 0.95, "timeframe": "immediate"}],
            "predicted_next_action": {"step": "Isolate Device", "rationale": "Limit further lateral movement", "confidence": 0.95, "timeframe": "immediate"},
            "recommendations": [{"id": "DEMO-ACT-01", "title": "Isolate Device", "description": "Isolate the compromised finance workstation.", "type": "CONTAINMENT", "status": "PENDING", "target": "WS-FINANCE-DEMO", "riskLevel": "HIGH"}],
            "risk": {"risk_score": 95, "risk_level": "CRITICAL", "breakdown": {"privilege_escalation": True, "critical_asset": True}},
            "confidence": 0.96,
            "confidence_breakdown": {"telemetry": 0.98, "correlation": 0.96},
            "evidence_references": refs,
            "proposed_playbook": {"name": "Demo Containment", "steps": [{"action_type": "Isolate Device", "target": "WS-FINANCE-DEMO", "description": "Isolate compromised workstation."}], "based_on": [r["evidence_id"] for r in refs]},
            "mitre_techniques": [getattr(e, "techniqueId", "") for e in events],
            "approval_requirement": {"required": True, "mode": "human", "auto_execute": False},
            "requires_user_approval": True,
            "auto_execute": False,
        })

