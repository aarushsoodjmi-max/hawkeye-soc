"""
event_generator.py
-------------------
Low-level utilities for generating synthetic SOC telemetry: users, devices,
IP addresses, timestamps, severities, and incident/alert identifiers.

This module has NO knowledge of specific attack scenarios — it only provides
building blocks that scenarios.py composes into realistic alert sequences.
"""

import random
import uuid
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Static reference pools used to generate believable synthetic data
# ---------------------------------------------------------------------------

FIRST_NAMES = [
    "james", "mary", "robert", "linda", "michael", "priya", "wei", "fatima",
    "carlos", "olga", "arjun", "sara", "noah", "emma", "liam", "ananya",
]

LAST_NAMES = [
    "smith", "johnson", "patel", "garcia", "chen", "kim", "khan", "ivanov",
    "silva", "muller", "nair", "brown", "lee", "gomez", "sharma", "davis",
]

DEPARTMENTS = ["finance", "hr", "engineering", "sales", "it", "legal", "exec"]

DEVICE_TYPES = ["WKS", "LAPTOP", "SRV", "VDI"]

OS_TYPES = ["Windows 11", "Windows 10", "macOS", "Ubuntu 22.04", "Windows Server 2022"]

SEVERITIES = ["Low", "Medium", "High", "Critical"]
SEVERITY_WEIGHTS_DEFAULT = [0.15, 0.35, 0.35, 0.15]

INTERNAL_SUBNET = "10.{octet2}.{octet3}.{octet4}"


def make_user(rng: random.Random) -> dict:
    """Generate a synthetic user identity."""
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    dept = rng.choice(DEPARTMENTS)
    return {
        "username": f"{first}.{last}",
        "department": dept,
    }


def make_device(rng: random.Random) -> dict:
    """Generate a synthetic device/host asset."""
    dtype = rng.choice(DEVICE_TYPES)
    hostname = f"{dtype}-{rng.randint(1000, 9999)}"
    return {
        "hostname": hostname,
        "os": rng.choice(OS_TYPES),
    }


def make_internal_ip(rng: random.Random) -> str:
    """Generate a synthetic RFC1918-style internal IP address."""
    return INTERNAL_SUBNET.format(
        octet2=rng.randint(0, 30),
        octet3=rng.randint(0, 255),
        octet4=rng.randint(2, 254),
    )


def make_external_ip(rng: random.Random) -> str:
    """Generate a synthetic external (public-looking) IP address."""
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def make_incident_id(rng: random.Random) -> str:
    """Generate a deterministic (seed-driven) incident identifier."""
    return f"INC-{rng.randint(100000, 999999)}"


def make_alert_id() -> str:
    """
    Generate a unique alert identifier.

    Intentionally NOT derived from the seeded RNG: it is a uniqueness key
    only, never used for branching simulation logic, so leaving it
    non-deterministic does not affect reproducibility of scenario content
    (severities, event order, users, etc. all remain deterministic).
    """
    return f"ALRT-{uuid.uuid4().hex[:10].upper()}"


def random_severity(rng: random.Random, weights=None) -> str:
    """Pick a severity level, optionally with custom weighting."""
    weights = weights or SEVERITY_WEIGHTS_DEFAULT
    return rng.choices(SEVERITIES, weights=weights, k=1)[0]


def timestamp_sequence(rng: random.Random, start: datetime, count: int,
                       min_gap_seconds: int = 30, max_gap_seconds: int = 150,
                       max_total_window_seconds: int = 1500) -> list[datetime]:
    """
    Generate `count` monotonically increasing timestamps starting at `start`,
    simulating an attack chain where all events occur strictly within
    `max_total_window_seconds` (default 25 minutes, fitting within the 30m window).
    """
    if count <= 0:
        return []
    if count == 1:
        return [start]

    target_span = min(max_total_window_seconds, count * max_gap_seconds)
    if min_gap_seconds * (count - 1) > target_span:
        min_gap_seconds = max(5, int(target_span / (count * 1.5)))

    timestamps = [start]
    current = start
    for i in range(count - 1):
        remaining_events = count - 1 - i
        elapsed = (current - start).total_seconds()
        remaining_time = max(10, target_span - elapsed)
        max_possible_gap = int(remaining_time / remaining_events)
        high = max(min_gap_seconds + 5, min(max_gap_seconds, max_possible_gap))
        low = min(min_gap_seconds, high - 1)
        gap = rng.randint(max(5, low), max(10, high))
        current = current + timedelta(seconds=gap)
        timestamps.append(current)
    return timestamps


def random_start_time(rng: random.Random, days_back: int = 0) -> datetime:
    """
    Pick a scenario start time so that generated attack events complete recently
    (e.g., within the last 25 minutes relative to now), or within past days if days_back > 0.
    """
    now = datetime.utcnow()
    if days_back > 0:
        anchor = now.replace(hour=0, minute=0, second=0, microsecond=0)
        delta_seconds = rng.randint(0, days_back * 24 * 3600)
        return anchor - timedelta(seconds=delta_seconds)
    
    # Live simulation: start 22-26 minutes ago so attack chain finishes right before now
    minutes_ago = rng.randint(22, 26)
    return now - timedelta(minutes=minutes_ago)


def build_alert(*, timestamp, incident_id, scenario, user, device, src_ip,
                 dst_ip, event_type, description, severity, mitre_technique=None):
    """Assemble a single alert record as a flat dict (one DataFrame row)."""
    return {
        "alert_id": make_alert_id(),
        "incident_id": incident_id,
        "timestamp": timestamp,
        "scenario": scenario,
        "username": user["username"],
        "department": user["department"],
        "hostname": device["hostname"],
        "os": device["os"],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "event_type": event_type,
        "description": description,
        "severity": severity,
        "mitre_technique": mitre_technique or "",
    }
