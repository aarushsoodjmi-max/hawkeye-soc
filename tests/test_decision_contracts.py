"""Contract tests for prediction, confidence, temporal knowledge graph,
decision simulator, playbook approval gate, and incident memory."""

from __future__ import annotations

from app.modules.prediction.service import predict_incident
from app.modules.confidence_engine.service import compute_confidence
from app.modules.decision_simulator.service import simulate
from app.modules.knowledge_graph.service import build_incident_knowledge_graph
from app.modules.incident_memory.service import IncidentMemoryService


def incident_dict():
    return {
        "id": "INC-CONTRACT-1",
        "severity": "CRITICAL",
        "status": "ACTIVE",
        "threatActor": "APT-CONTRACT",
        "affectedAssets": [
            {"id": "A1", "name": "HOST-1", "criticality": "TIER 0", "status": "COMPROMISED"},
            {"id": "A2", "name": "HOST-2", "criticality": "TIER 2", "status": "MONITORED"},
        ],
        "rootCause": {
            "primary": "compromised_account",
            "confidence": 0.88,
            "cveId": "CVE-2026-0001",
            "compromisedAccount": "svc_test",
            "c2Server": "1.2.3.4",
        },
        "timelineEvents": [
            {"timestamp": "2026-09-07T00:00:00Z", "technique": "Kerberoasting", "techniqueId": "T1558.003", "source": "Identity", "target": "HOST-1", "severity": "HIGH", "title": "Kerberoasting", "evidenceConfidence": 95.0},
            {"timestamp": "2026-09-07T00:01:00Z", "technique": "Remote Services", "techniqueId": "T1021", "source": "EDR", "target": "HOST-2", "severity": "HIGH", "title": "Remote Services", "evidenceConfidence": 90.0},
        ],
        "alerts": [{"host": "HOST-3", "user": "svc_test"}],
        "incident_id": "INC-CONTRACT-1",
    }


def test_prediction_contract():
    prediction = predict_incident(incident_dict())
    assert prediction["incident_id"] == "INC-CONTRACT-1"
    assert prediction["prediction"]
    assert 0 <= prediction["confidence"] <= 1
    assert prediction["relevant_evidence"]  # non-empty structured evidence
    assert prediction["timestamp"]
    assert prediction["status"] == "ACTIVE"
    assert prediction["overall_confidence"] == prediction["confidence"]
    assert "next_affected_assets" in prediction
    assert "lateral_movement" in prediction


def test_confidence_contract_unified():
    confidence = compute_confidence(incident_dict())
    assert abs(sum(confidence["weights"].values()) - 1.0) < 1e-9
    assert 0 <= confidence["unified_confidence"] <= 1
    assert confidence["subject_type"] == "incident"
    assert confidence["subject_id"] == "INC-CONTRACT-1"
    assert set(confidence["breakdown"]) == {"correlation", "ml", "threat_intel", "data_quality", "evidence_completeness"}
    assert confidence["computed_at"]
    assert "confidence_partial" in confidence


def test_temporal_knowledge_graph_contract():
    kg = build_incident_knowledge_graph(incident_dict())
    assert kg["canonical"] is True
    assert kg["incident_id"] == "INC-CONTRACT-1"
    node_types = {n["type"] for n in kg["nodes"]}
    assert {"incident", "asset", "identity", "indicator", "technique"} <= node_types
    for rel in kg["relationships"]:
        assert "valid_from" in rel
        assert "valid_to" in rel
        assert "relationship_type" in rel
        assert 0 <= rel["confidence"] <= 1
    assert any(r["relationship_type"] == "impacts_asset" for r in kg["relationships"])
    assert any(r["relationship_type"] == "uses_technique" for r in kg["relationships"])


def test_decision_simulator_contract():
    sim = simulate(incident_dict(), {"A1": [{"asset_id": "DB-1", "confidence": 0.8}]})
    assert sim.incident_id == "INC-CONTRACT-1"
    assert 0 <= sim.confidence_score <= 1
    assert sim.estimated_downtime_hours > 0
    assert sim.recovery_time_hours > 0
    assert sim.recovery_sequence
    assert sim.affected_departments


def test_incident_memory_structured_retrieval_only():
    svc = IncidentMemoryService()
    first = incident_dict()
    svc.record_closed(first, workspace_id="contract-pattern-test")
    second = dict(first)
    second["id"] = "INC-CONTRACT-2"
    second["incident_id"] = "INC-CONTRACT-2"
    svc.record_closed(second, workspace_id="contract-pattern-test")
    similar = svc.similar(first, workspace_id="contract-pattern-test")
    assert similar[0]["incident_id"] == "INC-CONTRACT-2"
    patterns = svc.get_patterns(workspace_id="contract-pattern-test")
    assert patterns[0]["occurrence_count"] == 2
    # structured retrieval: no vector index involved
    assert hasattr(svc, "signature")
