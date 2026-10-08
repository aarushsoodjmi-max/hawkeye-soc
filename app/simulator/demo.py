"""End-to-end deterministic demo runner for Hawkeye.

The runner exercises production services in order. AI uses a deterministic
provider adapter only when ``--demo-ai`` is selected, making the demo runnable
without an external LLM while preserving the real AI contract and all safety
controls. Production provider selection is unchanged.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from typing import Any

from app.core.audit import audit_log
from app.modules.ai.orchestration.context_builder import ContextBuilder
from app.modules.ai.orchestration.orchestrator import AiOrchestrator
from app.modules.decision_engine.service import generate_strategies
from app.modules.decision_simulator.service import simulate
from app.modules.playbooks.service import approve_playbook, create_playbook, execute_playbook
from app.repositories import repository
from app.simulator.demo_scenario import DEMO_INCIDENT_ID, DEMO_SEED, DEMO_WORKSPACE, build_demo_alerts


from app.modules.ai.providers.demo import DeterministicDemoProvider


@dataclass
class DemoResult:
    workspace_id: str
    incident_id: str
    alert_count: int
    ai_summary: str
    simulation: dict
    playbook_id: str
    execution_state: str
    verification: dict
    executive_report: dict
    resolved: bool


def reset_demo(workspace: str = DEMO_WORKSPACE) -> None:
    for kind in ("events", "normalized_events", "incidents", "assets", "entities", "knowledge_graph", "threat_intelligence", "risk", "prediction", "confidence", "incident_memory", "decisions", "simulations", "playbooks", "playbook_executions", "event_dispatches"):
        repository._persistent.delete_workspace(kind, workspace)
    removed_alert_ids = [str(a.id) for a in repository.alerts if repository._workspace_for(a) == workspace]
    repository.alerts[:] = [a for a in repository.alerts if repository._workspace_for(a) != workspace]
    for aid in removed_alert_ids:
        repository._index.pop(f"{workspace}:{aid}", None)
        if workspace == "default":
            repository._index.pop(aid, None)
    for iid, incident in list(repository.incidents.items()):
        if repository._workspace_for(incident) == workspace:
            repository.incidents.pop(iid, None)
            repository._index.pop(str(iid), None)
            repository._index.pop(f"{workspace}:{getattr(incident, 'id', iid)}", None)


def run_demo(workspace: str = DEMO_WORKSPACE, reset: bool = True, deterministic_ai: bool = True) -> DemoResult:
    if reset:
        reset_demo(workspace)
    alerts = build_demo_alerts()
    ingested, incident_id = repository.ingest_alerts(alerts, scenario_hint="credential_compromise_demo", workspace=workspace)
    if incident_id is None:
        incident_id = DEMO_INCIDENT_ID
    incident = repository.get_incident_by_id(incident_id, workspace=workspace)
    if incident is None:
        raise RuntimeError("demo incident was not created")

    evidence = ContextBuilder(repository=repository).build_from_incident(incident, workspace_id=workspace)
    if deterministic_ai:
        from app.modules.ai.providers.base import ProviderRegistry
        orch = AiOrchestrator(registry=ProviderRegistry([DeterministicDemoProvider()]), default_provider="demo", context_builder=ContextBuilder(repository=repository))
        ai = orch.analyze(type("Req", (), {"incident_id": incident_id, "workspace_id": workspace, "task": "investigate", "analyst_instructions": None, "options": None})(), evidence=evidence, provider="demo")
    else:
        from app.modules.ai import get_default_registry
        from app.modules.ai.contracts.requests import AiRequest
        ai = AiOrchestrator(registry=get_default_registry(), context_builder=ContextBuilder(repository=repository)).analyze(AiRequest(incident_id=incident_id, workspace_id=workspace, task="investigate"), evidence=evidence, provider="local")

    simulation = simulate(incident, getattr(incident, "assetDependencies", {}) or {}).model_dump(mode="json")
    incident.latestSimulation = simulation
    repository._persist_incident(incident, workspace)
    playbook = create_playbook(incident_id, ["Isolate Device"], target="WS-FINANCE-DEMO", actor="demo-analyst", workspace_id=workspace)
    approved = approve_playbook(playbook.playbook_id, approver="demo-admin", incident_id=incident_id, workspace_id=workspace)
    if not approved:
        raise RuntimeError("demo playbook approval failed")
    executed = execute_playbook(playbook.playbook_id, executor="demo-operator", incident_id=incident_id, workspace_id=workspace)
    resolved = executed.get("state") == "EXECUTED"
    if resolved:
        repository.update_incident_status(incident_id, "RESOLVED", workspace=workspace)

    from app.services.transport_service import ReportService
    executive_report = ReportService().executive(incident_id, workspace=workspace) or {}
    return DemoResult(workspace, incident_id, len(ingested), ai.summary, simulation, playbook.playbook_id, executed.get("state", "UNKNOWN"), executed.get("execution", {}).get("verification", {}), executive_report, resolved)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the deterministic Hawkeye end-to-end demo")
    parser.add_argument("--workspace", default=DEMO_WORKSPACE)
    parser.add_argument("--no-reset", action="store_true")
    parser.add_argument("--real-ai", action="store_true", help="Use configured LocalProvider instead of offline deterministic demo AI")
    args = parser.parse_args()
    result = run_demo(args.workspace, reset=not args.no_reset, deterministic_ai=not args.real_ai)
    print(json.dumps(asdict(result), indent=2, default=str))
    return 0 if result.resolved else 1


if __name__ == "__main__":
    raise SystemExit(main())
