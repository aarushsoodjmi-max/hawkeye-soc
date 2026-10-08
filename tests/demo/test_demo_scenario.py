from app.simulator.demo_scenario import build_demo_alerts, demo_fingerprint, DEMO_SEED


def test_demo_scenario_is_deterministic():
    first = build_demo_alerts()
    second = build_demo_alerts()
    assert first == second
    assert demo_fingerprint()
    assert len(first) == 8
    assert [x["title"] for x in first] == [
        "Credential Compromise", "Impossible Travel", "VPN Login", "PowerShell",
        "Credential Access", "Lateral Movement", "Privileged Account", "Critical Server",
    ]
    assert all(x["metadata"]["demo_seed"] == DEMO_SEED for x in first)
