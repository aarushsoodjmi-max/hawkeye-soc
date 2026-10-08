"""Deterministic end-to-end Hawkeye demo scenario.

This is deliberately separate from production detection logic. It supplies a
stable sequence of synthetic telemetry to the real ingestion/correlation and
intelligence services so demos and smoke tests exercise the same backend
contracts used by live data.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any

DEMO_WORKSPACE = "demo-workspace"
DEMO_INCIDENT_ID = "INC-DEMO-0001"
DEMO_USER = "alex.morgan"
DEMO_HOST = "WS-FINANCE-DEMO"
DEMO_SERVER = "SRV-PAYMENTS-DEMO"
DEMO_SOURCE_IP = "203.0.113.42"
DEMO_VPN_IP = "198.51.100.24"
DEMO_CRITICAL_IP = "10.20.30.40"
DEMO_SEED = 4101


def _ts(index: int) -> str:
    base = datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)
    return (base + timedelta(minutes=index * 3)).isoformat().replace("+00:00", "Z")


def build_demo_alerts() -> list[dict[str, Any]]:
    steps = [
        ("Credential Compromise", "T1078", "Valid Accounts", "Compromised credential accepted for alex.morgan from an anomalous source.", "HIGH"),
        ("Impossible Travel", "T1078", "Valid Accounts", "Login for alex.morgan occurred from New York shortly after a London session.", "HIGH"),
        ("VPN Login", "T1133", "External Remote Services", "VPN session established from the anomalous source address.", "HIGH"),
        ("PowerShell", "T1059.001", "PowerShell", "PowerShell spawned from the VPN session on the finance workstation.", "HIGH"),
        ("Credential Access", "T1003.001", "OS Credential Dumping", "Credential material was accessed from LSASS memory.", "CRITICAL"),
        ("Lateral Movement", "T1021.002", "SMB/Windows Admin Shares", "Authenticated SMB movement from the workstation to the payment server.", "CRITICAL"),
        ("Privileged Account", "T1078.002", "Domain Accounts", "A privileged domain account was used during lateral movement.", "CRITICAL"),
        ("Critical Server", "T1021.002", "SMB/Windows Admin Shares", "Suspicious administrative access reached the critical payment server.", "CRITICAL"),
    ]
    alerts = []
    for idx, (title, technique_id, technique, description, severity) in enumerate(steps, 1):
        event_id = f"DEMO-EVT-{idx:02d}"
        alerts.append({
            "id": event_id,
            "alert_id": event_id,
            "incident_id": DEMO_INCIDENT_ID,
            "title": title,
            "severity": severity,
            "category": "Demo Attack Chain",
            "sourceIp": DEMO_SOURCE_IP if idx < 3 else DEMO_VPN_IP,
            "destinationIp": DEMO_CRITICAL_IP if idx >= 6 else "10.20.10.10",
            "host": DEMO_HOST if idx < 6 else DEMO_SERVER,
            "user": DEMO_USER if idx < 7 else "domain-admin-demo",
            "timestamp": _ts(idx),
            "mitreTactic": "Credential Access" if idx in (1, 2, 5) else "Lateral Movement" if idx >= 6 else "Execution",
            "mitreTechnique": technique,
            "techniqueId": technique_id,
            "status": "NEW",
            "confidenceScore": 96.0 + min(idx, 3),
            "source": "Hawkeye Deterministic Demo",
            "description": description,
            "rawLog": f"DEMO[{idx}] {title}: {description}",
            "metadata": {"demo": True, "demo_seed": DEMO_SEED, "workspace": DEMO_WORKSPACE},
        })
    return alerts


def demo_fingerprint() -> str:
    raw = "|".join(a["id"] + a["timestamp"] for a in build_demo_alerts())
    return sha256(raw.encode()).hexdigest()
