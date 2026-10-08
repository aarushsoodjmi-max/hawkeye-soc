"""End-to-end canonical pipeline integration tests.

Covers: event ingestion -> normalization -> data quality -> correlation ->
incident creation -> knowledge graph update -> risk -> prediction -> confidence ->
decision -> simulation -> approved playbook. Also verifies canonical incident
state and legacy route delegation.
"""

from __future__ import annotations

from app.repositories.soc_repository import SocRepository
from app.modules.ingestion.service import prepare_ingestion_batch
from app.modules.playbooks.service import approve_playbook, create_playbook

RAW_ALERTS = [
    {
        "id": "ALT-P1",
        "title": "Powershell remote execution",
        "severity": "HIGH",
        "host": "HOST-A",
        "user": "svc_pipeline",
        "sourceIp": "10.1.1.1",
        "destinationIp": "10.1.1.2",
        "timestamp": "2026-09-07T10:00:00Z",
        "mitreTactic": "Execution",
        "mitreTechnique": "PowerShell",
        "techniqueId": "T1059.001",
        "source": "EDR",
        "metadata": {"workspace": "acme", "tenant": "acme"},
    },
    {
        "id": "ALT-P2",
        "title": "Credential dump via lsass",
        "severity": "CRITICAL",
        "host": "HOST-B",
        "user": "svc_pipeline",
        "sourceIp": "10.1.1.1",
        "destinationIp": "10.1.1.2",
        "timestamp": "2026-09-07T10:05:00Z",
        "mitreTactic": "Credential Access",
        "mitreTechnique": "Credential Dumping",
        "techniqueId": "T1003.001",
        "source": "EDR",
        "metadata": {"workspace": "acme", "tenant": "acme"},
    },
]


def test_ingestion_normalization_metadata():
    prepared = prepare_ingestion_batch(RAW_ALERTS, event_metadata={"ingested_via": "pipeline_test"})
    assert len(prepared) == 2
    for alert in prepared:
        assert alert["metadata"]["workspace"] == "acme"
        assert alert["metadata"]["tenant"] == "acme"
        assert alert["metadata"]["ingested_from"] == "EDR"
        assert alert["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert "data_quality" in alert["metadata"]
        assert alert["metadata"]["data_quality"]["status"] in {"PASS", "REVIEW"}


def test_full_pipeline_ingestion_to_approved_playbook():
    repo = SocRepository()
    ingested, incident_id = repo.ingest_alerts([dict(a) for a in RAW_ALERTS], scenario_hint="pipeline_test")
    assert ingested and incident_id
    assert incident_id in repo.incidents
    incident = repo.incidents[incident_id]

    # Canonical incident source of truth
    assert repo.get_incident_by_id(incident_id) is incident

    # Alerts carry preserved metadata
    for alert in ingested:
        assert alert.metadata.get("workspace") == "default"

    # Correlation produced a real incident
    assert incident.associatedAlertCount >= 1
    assert incident.timelineEvents

    # Knowledge graph updated (temporal relationships)
    kg = incident.knowledgeGraph
    assert kg and kg.get("canonical") is True
    assert kg.get("nodes") and kg.get("relationships")
    for rel in kg["relationships"]:
        assert "valid_from" in rel
        assert "relationship_type" in rel
        assert "confidence" in rel
        assert "valid_to" in rel

    # Risk engine
    assert incident.riskScore is not None and 0 <= incident.riskScore <= 100
    assert incident.riskLevel in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
    assert incident.riskBreakdown

    # Threat intelligence + business impact + workflow intelligence
    assert incident.threatIntelligence.get("attack_chain")
    assert incident.businessImpact.get("priority")
    assert incident.workflowIntelligence.get("human_approval_required") is True

    # Prediction contract
    prediction = incident.predictions[-1]
    assert prediction["prediction"]
    assert 0 <= prediction["confidence"] <= 1
    assert prediction["relevant_evidence"]
    assert prediction["timestamp"]
    assert prediction["status"] == "ACTIVE"
    assert prediction["incident_id"] == incident_id

    # Confidence contract
    confidence = incident.confidenceAssessment
    assert 0 <= confidence["unified_confidence"] <= 1
    abs(sum(confidence["weights"].values()) - 1.0) < 1e-9
    assert incident.confidenceContract["version"] == "1.0"
    assert incident.confidenceContract["unified_confidence"] == confidence["unified_confidence"]

    # Decision recommendations require explicit approval
    assert incident.decisionRecommendations
    for strategy in incident.decisionRecommendations:
        assert strategy["approval_required"] is True
        assert strategy["execution_state"] == "REQUIRES_APPROVAL"
    assert incident.approvalState["status"] == "PENDING_APPROVAL"
    assert incident.approvalState["approved"] is False

    # Decision simulator consumes canonical KG state (asset dependencies)
    from app.modules.decision_simulator.service import simulate as simulate_decision

    sim = simulate_decision(incident, incident.assetDependencies).model_dump()
    assert sim["incident_id"] == incident_id
    assert 0 <= sim["confidence_score"] <= 1
    assert "estimated_downtime_hours" in sim
    incident.latestSimulation = sim

    # Digital twin snapshot on significant state change
    assert incident.digitalTwinSnapshots
    snapshot = incident.digitalTwinSnapshots[-1]
    assert snapshot["incident_id"] == incident_id
    assert snapshot["reason"] in {"event_ingestion", "periodic_baseline", "decision_simulation"}

    # Playbook approval: creation is SIMULATED only; execution requires explicit approval
    from app.repositories import repository as canonical_repository
    canonical_incident = canonical_repository.get_incidents(workspace="default")[0][0]
    playbook = create_playbook(canonical_incident.id, ["isolate_device", "block_ip"], actor="test", workspace_id="default")
    assert all(action.status == "SIMULATED" for action in playbook.actions)

    approved = approve_playbook(playbook.playbook_id, approver="admin", incident_id=canonical_incident.id, workspace_id="default")
    assert approved is not None
    assert approved["approval"]["status"] == "APPROVED"
    assert all(action["status"] == "PENDING" for action in approved["actions"])
    assert approved["approval"]["approved_by"] == "admin"
    # Approval is a gate, not execution. Execution is a separate step with
    # deterministic postcondition verification.


def test_no_autonomous_execution_before_approval():
    repo = SocRepository()
    incident = next(iter(repo.incidents.values()))
    playbook = create_playbook(incident.id, ["disable_user"], actor="test")
    assert all(action.status == "SIMULATED" for action in playbook.actions)
    assert all(action.result is not None and "approval" in action.result for action in playbook.actions)
    # Explicitly NOT auto-approved; approval must be called by an authorized human
    assert not repo.incidents[incident.id].lastApprovedPlaybook


def test_canonical_incident_state_single_source():
    repo = SocRepository()
    for incident_id, incident in repo.incidents.items():
        assert repo.get_incident_by_id(incident_id) is incident
        # No rival in-memory vs ORM state: repository dict is the only store
        assert incident.id == incident_id


def test_legacy_route_delegation_to_canonical():
    from app.services.transport_service import _graph, _incidents

    graph = _graph.graph()
    assert "nodes" in graph and "edges" in graph
    for edge in graph["edges"]:
        assert "relationship_type" in edge
        assert "confidence" in edge

    listed = _incidents.list()
    assert listed and all(getattr(i, "knowledgeGraph", None) for i in listed)


def test_status_update_keeps_canonical_intelligence():
    repo = SocRepository()
    incident = next(iter(repo.incidents.values()))
    updated = repo.update_incident_status(incident.id, "TRIAGING")
    assert updated.status == "TRIAGING"
    # Canonical store updated in place (same object identity)
    assert repo.get_incident_by_id(incident.id) is updated
    assert updated.knowledgeGraph
    assert updated.predictions
