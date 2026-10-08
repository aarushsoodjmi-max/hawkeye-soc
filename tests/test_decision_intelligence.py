from app.modules.prediction.service import predict_incident
from app.modules.incident_memory.service import IncidentMemoryService
from app.modules.confidence_engine.service import compute_confidence


def incident():
    return {
        "id": "INC-TEST-1", "severity": "HIGH", "threatActor": "Test Actor",
        "affectedAssets": [{"id":"A1","name":"HOST-1","criticality":"TIER 1"}, {"id":"A2","name":"HOST-2","criticality":"TIER 2"}],
        "rootCause": {"primary":"compromised_account","confidence":0.88,"cveId":"CVE-2024-3400","compromisedAccount":"svc_test","c2Server":"1.2.3.4"},
        "timelineEvents": [
            {"timestamp":"2026-01-01T00:00:00Z","technique":"Remote Services","techniqueId":"T1021","source":"EDR","target":"HOST-1","severity":"HIGH","evidenceConfidence":90},
            {"timestamp":"2026-01-01T00:01:00Z","technique":"Kerberoasting","techniqueId":"T1558.003","source":"Identity","target":"HOST-2","severity":"HIGH","evidenceConfidence":95},
        ],
        "alerts": [{"host":"HOST-3","user":"alice"}],
        "recommendedActions": [{"playbookId":"PB-1","status":"COMPLETED"}],
        "impactSummary":"Test incident",
        "status":"CLOSED"
    }

def test_prediction_contract():
    p=predict_incident(incident())
    assert p["incident_id"] == "INC-TEST-1"
    assert "next_affected_assets" in p and "lateral_movement" in p
    assert 0 <= p["overall_confidence"] <= 1

def test_memory_similarity_and_pattern():
    svc=IncidentMemoryService(); i=incident(); svc.record_closed(i, workspace_id="decision-pattern-test")
    i2=dict(i); i2["id"]="INC-TEST-2"; i2["rootCause"]={**i["rootCause"]}
    svc.record_closed(i2, workspace_id="decision-pattern-test")
    assert svc.similar(i, workspace_id="decision-pattern-test")[0]["incident_id"] == "INC-TEST-2"
    assert svc.get_patterns(workspace_id="decision-pattern-test")[0]["occurrence_count"] == 2

def test_confidence_weights_sum_to_one():
    c=compute_confidence(incident())
    assert abs(sum(c["weights"].values()) - 1.0) < 1e-9
    assert 0 <= c["unified_confidence"] <= 1
    assert set(c["breakdown"]) == {"correlation","ml","threat_intel","data_quality","evidence_completeness"}
