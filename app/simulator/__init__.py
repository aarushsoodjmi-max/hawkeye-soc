"""Synthetic attack simulation and deterministic demo helpers."""
from .attack_simulator import AttackSimulator, simulate
from .demo_scenario import build_demo_alerts, DEMO_SEED, DEMO_WORKSPACE, DEMO_INCIDENT_ID

__all__ = ["AttackSimulator", "simulate", "build_demo_alerts", "DEMO_SEED", "DEMO_WORKSPACE", "DEMO_INCIDENT_ID"]
