from app.simulator.demo import run_demo, reset_demo


def test_demo_pipeline_end_to_end():
    workspace = "demo-test-pipeline"
    reset_demo(workspace)
    result = run_demo(workspace=workspace, reset=True, deterministic_ai=True)
    assert result.alert_count == 8
    assert result.execution_state == "EXECUTED"
    assert result.verification["status"] == "VERIFIED"
    assert result.resolved is True
    assert result.executive_report["incident_id"] == result.incident_id
    assert result.executive_report["status"] == "RESOLVED"
    reset_demo(workspace)
