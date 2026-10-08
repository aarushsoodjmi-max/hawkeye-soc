"""
generate_dataset.py
--------------------
Synthetic SOC (Security Operations Center) alert telemetry generator
for the "Causal SOC Alert Correlation & Root Cause Intelligence"
project (HawkEye SOC).

This script produces a single CSV file (alerts.csv) containing ~1000
FULLY SYNTHETIC security alerts. No real user, device, IP, or incident
data is used anywhere in this module.

A subset of the malicious alerts are grouped into "incidents" --
causally linked chains of 3-6 alerts (e.g. phishing_email ->
login_anomaly -> privilege_escalation -> data_access ->
outbound_connection) that all share the same incident_id, following a
plausible attack-stage "playbook" for a randomly chosen root cause.
The remaining alerts (benign noise and isolated / unlinked malicious
events) have no incident_id.

This module ONLY generates and writes data. It does not correlate
alerts, does not train or run any model, and exposes no API/service
layer -- that is intentionally out of scope for this file.

Usage:
    python generate_dataset.py
"""

import csv
import random
from datetime import datetime, timedelta

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

RANDOM_SEED = 42

TOTAL_ALERTS_TARGET = 1000
BENIGN_COUNT = 700
MALICIOUS_COUNT = TOTAL_ALERTS_TARGET - BENIGN_COUNT  # 300

NUM_INCIDENTS = 30
MIN_ALERTS_PER_INCIDENT = 3
MAX_ALERTS_PER_INCIDENT = 6

from pathlib import Path

OUTPUT_PATH = str(Path(__file__).parent / "alerts.csv")

ALERT_TYPES = [
    "login_anomaly",
    "powershell_exec",
    "privilege_escalation",
    "data_access",
    "malware_detected",
    "phishing_email",
    "outbound_connection",
    "credential_dump",
]

SEVERITIES = ["low", "medium", "high", "critical"]

ROOT_CAUSES_MALICIOUS = ["compromised_account", "malware", "phishing", "insider"]
ROOT_CAUSE_BENIGN = "benign"

SOURCES = ["EDR", "SIEM", "Firewall", "IDS", "Email Gateway", "AD", "DLP", "Proxy"]

# Alert type -> plausible telemetry source(s)
ALERT_SOURCE_MAP = {
    "login_anomaly": ["AD", "SIEM"],
    "powershell_exec": ["EDR"],
    "privilege_escalation": ["EDR", "AD"],
    "data_access": ["DLP", "SIEM"],
    "malware_detected": ["EDR"],
    "phishing_email": ["Email Gateway"],
    "outbound_connection": ["Firewall", "Proxy"],
    "credential_dump": ["EDR"],
}

# Baseline severity leaning per alert type (jittered by random.choice)
ALERT_SEVERITY_BIAS = {
    "login_anomaly": ["low", "medium"],
    "powershell_exec": ["medium", "high"],
    "privilege_escalation": ["high", "critical"],
    "data_access": ["medium", "high"],
    "malware_detected": ["high", "critical"],
    "phishing_email": ["low", "medium"],
    "outbound_connection": ["medium", "high"],
    "credential_dump": ["high", "critical"],
}

# Causal "playbooks" per root cause: ordered stages of a plausible
# attack chain. Each incident samples a contiguous slice (length 3-6)
# of one playbook, in order, to simulate a causally-linked chain.
ROOT_CAUSE_PLAYBOOKS = {
    "phishing": [
        "phishing_email",
        "login_anomaly",
        "powershell_exec",
        "privilege_escalation",
        "data_access",
        "outbound_connection",
    ],
    "compromised_account": [
        "login_anomaly",
        "privilege_escalation",
        "powershell_exec",
        "credential_dump",
        "data_access",
        "outbound_connection",
    ],
    "malware": [
        "malware_detected",
        "powershell_exec",
        "privilege_escalation",
        "credential_dump",
        "outbound_connection",
    ],
    "insider": [
        "login_anomaly",
        "data_access",
        "privilege_escalation",
        "outbound_connection",
    ],
}

FIRST_NAMES = [
    "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
    "william", "elizabeth", "david", "barbara", "richard", "susan", "joseph", "jessica",
    "thomas", "sarah", "charles", "karen", "arjun", "priya", "wei", "mei", "carlos",
    "sofia", "ahmed", "fatima", "yusuf", "elena",
]
LAST_INITIALS = list("abcdefghijklmnopqrstuvwxyz")

DEVICE_PREFIXES = ["WIN10", "WIN11", "MACOS", "SRV-DB", "SRV-WEB", "SRV-FILE", "LNX-APP"]

# --------------------------------------------------------------------------
# Helper generators
# --------------------------------------------------------------------------

def _build_user_pool(n=120):
    """Return a sorted list of n synthetic usernames, e.g. 'james.k'."""
    users = set()
    while len(users) < n:
        first = random.choice(FIRST_NAMES)
        initial = random.choice(LAST_INITIALS)
        users.add(f"{first}.{initial}")
    return sorted(users)


def _build_device_pool(n=80):
    """Return a sorted list of n synthetic hostnames, e.g. 'WIN10-042'."""
    devices = set()
    while len(devices) < n:
        prefix = random.choice(DEVICE_PREFIXES)
        num = random.randint(1, 999)
        devices.add(f"{prefix}-{num:03d}")
    return sorted(devices)


def _internal_ip():
    """Synthetic RFC1918-style internal IP (10.x.x.x)."""
    return f"10.{random.randint(0, 30)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def _external_ip():
    """Synthetic-looking public IP for 'attacker infrastructure' flavor."""
    first_octet = random.choice([45, 61, 78, 91, 103, 118, 141, 172, 185, 203])
    return f"{first_octet}.{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def _random_timestamp(start, end):
    delta = end - start
    seconds = random.randint(0, max(int(delta.total_seconds()), 1))
    return start + timedelta(seconds=seconds)


def _severity_for(alert_type):
    return random.choice(ALERT_SEVERITY_BIAS.get(alert_type, SEVERITIES))


def _source_for(alert_type):
    return random.choice(ALERT_SOURCE_MAP.get(alert_type, SOURCES))


# --------------------------------------------------------------------------
# Core generation logic
# --------------------------------------------------------------------------

def generate_incident_alerts(incident_index, users, devices, window_start, window_end):
    """Generate one causally-linked incident: 3-6 alerts sharing a single
    incident_id, following a plausible attack-stage playbook for a
    randomly chosen malicious root cause. Timestamps within an incident
    are ordered and clustered close together (minutes-to-hours apart) to
    simulate a real attack timeline.
    """
    root_cause = random.choice(ROOT_CAUSES_MALICIOUS)
    playbook = ROOT_CAUSE_PLAYBOOKS[root_cause]

    chain_len = random.randint(MIN_ALERTS_PER_INCIDENT, min(MAX_ALERTS_PER_INCIDENT, len(playbook)))
    start_idx = random.randint(0, len(playbook) - chain_len)
    stages = playbook[start_idx:start_idx + chain_len]

    incident_id = f"INC-{incident_index:04d}"
    user = random.choice(users)
    primary_device = random.choice(devices)
    secondary_device = random.choice(devices)  # possible lateral movement

    attacker_ip = _external_ip() if random.random() < 0.6 else _internal_ip()
    internal_ip = _internal_ip()

    incident_start = _random_timestamp(window_start, window_end - timedelta(hours=12))
    cursor = incident_start

    rows = []
    for i, stage in enumerate(stages):
        cursor = cursor + timedelta(minutes=random.randint(5, 240))
        device = primary_device if i < len(stages) - 1 or random.random() < 0.7 else secondary_device
        ip = attacker_ip if stage in ("outbound_connection", "phishing_email") else internal_ip

        rows.append({
            "timestamp": cursor.strftime("%Y-%m-%d %H:%M:%S"),
            "user": user,
            "device": device,
            "ip_address": ip,
            "alert_type": stage,
            "severity": _severity_for(stage),
            "source": _source_for(stage),
            "root_cause": root_cause,
            "incident_id": incident_id,
        })
    return rows


def generate_standalone_malicious_alert(users, devices, window_start, window_end, standalone_id=None):
    """A malicious alert that is NOT part of any labeled incident chain
    (an isolated / unlinked malicious event)."""
    root_cause = random.choice(ROOT_CAUSES_MALICIOUS)
    playbook = ROOT_CAUSE_PLAYBOOKS[root_cause]
    alert_type = random.choice(playbook)
    user = random.choice(users)
    device = random.choice(devices)
    is_net_stage = alert_type in ("outbound_connection", "phishing_email")
    ip = _external_ip() if is_net_stage and random.random() < 0.6 else _internal_ip()
    ts = _random_timestamp(window_start, window_end)

    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "device": device,
        "ip_address": ip,
        "alert_type": alert_type,
        "severity": _severity_for(alert_type),
        "source": _source_for(alert_type),
        "root_cause": root_cause,
        "incident_id": standalone_id or f"INC-S-{random.randint(10000, 99999)}",
    }


def generate_benign_alert(users, devices, window_start, window_end, benign_id=None):
    """A benign alert (false positive / normal activity flagged by a
    detector). Any alert_type can appear as benign -- this is intentional,
    since real SOCs see false positives across every rule type."""
    alert_type = random.choice(ALERT_TYPES)
    user = random.choice(users)
    device = random.choice(devices)
    ip = _internal_ip() if random.random() < 0.85 else _external_ip()
    ts = _random_timestamp(window_start, window_end)

    # Benign alerts skew toward lower severity.
    severity = random.choices(SEVERITIES, weights=[45, 35, 15, 5])[0]

    return {
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "device": device,
        "ip_address": ip,
        "alert_type": alert_type,
        "severity": severity,
        "source": _source_for(alert_type),
        "root_cause": ROOT_CAUSE_BENIGN,
        "incident_id": benign_id or f"BENIGN-{random.randint(10000, 99999)}",
    }


def generate_dataset():
    """Build the full list of alert dict rows (unshuffled generation order,
    then shuffled once) according to the configured distribution."""
    random.seed(RANDOM_SEED)

    users = _build_user_pool()
    devices = _build_device_pool()

    window_end = datetime(2026, 8, 31, 23, 59, 59)
    window_start = window_end - timedelta(days=30)

    all_rows = []

    # 1) Incidents: NUM_INCIDENTS incidents, 3-6 causally-linked alerts each.
    incident_alert_count = 0
    for i in range(1, NUM_INCIDENTS + 1):
        incident_rows = generate_incident_alerts(i, users, devices, window_start, window_end)
        all_rows.extend(incident_rows)
        incident_alert_count += len(incident_rows)

    # 2) Remaining standalone malicious alerts to reach MALICIOUS_COUNT.
    remaining_malicious = max(0, MALICIOUS_COUNT - incident_alert_count)
    for s_idx in range(1, remaining_malicious + 1):
        all_rows.append(generate_standalone_malicious_alert(
            users, devices, window_start, window_end, standalone_id=f"INC-S-{s_idx:05d}"
        ))

    # 3) Benign alerts - each gets a unique ID so they do not collapse into one incident.
    for b_idx in range(1, BENIGN_COUNT + 1):
        all_rows.append(generate_benign_alert(
            users, devices, window_start, window_end, benign_id=f"BENIGN-{b_idx:05d}"
        ))

    random.shuffle(all_rows)
    return all_rows


def write_csv(rows, path=OUTPUT_PATH):
    fieldnames = [
        "timestamp", "user", "device", "ip_address", "alert_type",
        "severity", "source", "root_cause", "incident_id",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main():
    rows = generate_dataset()
    write_csv(rows, OUTPUT_PATH)

    total = len(rows)
    malicious = sum(1 for r in rows if r["root_cause"] != ROOT_CAUSE_BENIGN)
    benign = total - malicious
    incidents = len({r["incident_id"] for r in rows if r["incident_id"]})

    print(f"Generated {total} alerts -> {OUTPUT_PATH}")
    print(f"  benign:    {benign}")
    print(f"  malicious: {malicious}")
    print(f"  incidents: {incidents}")


if __name__ == "__main__":
    main()
