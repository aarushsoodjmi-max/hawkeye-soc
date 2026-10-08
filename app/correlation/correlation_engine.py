"""
Causal Correlation Engine
==========================
Reconstructs security incidents from noisy, unordered SOC alerts by
performing entity resolution across user, device, and IP address
dimensions, constrained by a temporal window.

Design note on "all conditions match"
--------------------------------------
Two alerts are considered causally linked (an "edge") when they satisfy
BOTH of:
    (a) at least one shared entity dimension: same user, same device,
        or same source IP address
    (b) their timestamps fall within a 30 minute window of each other

Alerts are NOT required to match on all three entity dimensions to be
linked. Real attacks pivot — an attacker keeps the same user account but
switches devices, or keeps the same device but rotates IPs. Requiring a
strict match on user AND device AND IP simultaneously would silently
fail to correlate these pivoting alerts into a single incident, which
defeats the purpose of a "causal" correlation engine.

Instead, entity resolution builds a graph of alerts connected by shared
entities + time proximity, and takes the connected components of that
graph as candidate incidents (a transitive merge, via union-find). The
DEGREE to which alerts within a resulting incident actually agree on
user / device / IP / chronology is then captured separately by
`calculate_confidence`, using the exact point weights specified by the
project brief (user +30, device +25, ip +20, chronological +25).

This module is pure Python + pandas. No ML, no APIs, no frontend.
"""

from __future__ import annotations

import pandas as pd

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

from app.config import settings

REQUIRED_COLUMNS = [
    "timestamp", "user", "device", "ip_address",
    "alert_type", "severity", "source", "root_cause", "incident_id",
]

TIME_WINDOW_MINUTES = getattr(settings, "CORRELATION_WINDOW_MINUTES", 30)


# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------

class _UnionFind:
    """Minimal union-find (disjoint-set) helper used to cluster alert
    indices into connected components based on pairwise links.
    """

    def __init__(self, items):
        self.parent = {item: item for item in items}

    def find(self, item):
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _validate_and_prepare(df: pd.DataFrame) -> pd.DataFrame:
    """Validate required columns exist and normalize the timestamp column.

    Returns a copy of `df`, sorted chronologically, with `timestamp`
    coerced to pandas datetime and canonical columns guaranteed.
    """
    work = df.copy()

    # Normalize column names from common schemas
    alias_map = {}
    for col in work.columns:
        clow = str(col).lower().strip()
        if clow in ("username", "user_name"):
            alias_map[col] = "user"
        elif clow in ("hostname", "host", "device_name"):
            alias_map[col] = "device"
        elif clow in ("src_ip", "source_ip", "sourceip"):
            if "ip_address" not in work.columns and "ip_address" not in alias_map.values():
                alias_map[col] = "ip_address"
        elif clow in ("event_type", "title", "name"):
            alias_map[col] = "alert_type"
        elif clow in ("sev",):
            alias_map[col] = "severity"
        elif clow in ("scenario", "rootcause"):
            alias_map[col] = "root_cause"

    if alias_map:
        work = work.rename(columns=alias_map)

    # Supply default values for missing required columns
    defaults = {
        "timestamp": pd.Timestamp.utcnow(),
        "user": "unknown_user",
        "device": "unknown_device",
        "ip_address": "0.0.0.0",
        "alert_type": "security_alert",
        "severity": "low",
        "source": "EDR",
        "root_cause": None,
        "incident_id": None,
    }
    for col, default_val in defaults.items():
        if col not in work.columns:
            work[col] = default_val

    work["timestamp"] = pd.to_datetime(work["timestamp"], utc=True)
    work = work.sort_values("timestamp").reset_index(drop=True)
    return work


def _alerts_linked(a: pd.Series, b: pd.Series, window_minutes: float | None = None) -> bool:
    """Return True if two alert rows should be linked into the same incident.

    Linked = shares at least one of (user, device, ip_address, non-benign incident_id)
    AND the time delta between the two alerts is <= window_minutes.
    """
    win = window_minutes if window_minutes is not None else TIME_WINDOW_MINUTES
    time_delta_minutes = abs((a["timestamp"] - b["timestamp"]).total_seconds()) / 60.0
    if time_delta_minutes > win:
        return False

    def _val(v):
        if pd.isna(v):
            return None
        s = str(v).strip()
        return s.lower() if s else None

    # Check shared explicit non-benign incident ID first
    inc_a, inc_b = _val(a.get("incident_id")), _val(b.get("incident_id"))
    if (
        inc_a
        and inc_b
        and inc_a == inc_b
        and not inc_a.startswith("benign")
        and not inc_a.startswith("inc-sim")
        and inc_a not in ("none", "null", "undefined", "inc-sim")
    ):
        return True

    user_a, user_b = _val(a.get("user")), _val(b.get("user"))
    dev_a, dev_b = _val(a.get("device")), _val(b.get("device"))

    # Extract all candidate IPs for a and b
    def _extract_ips(row: pd.Series) -> set[str]:
        ips = set()
        for field in ("ip_address", "src_ip", "dst_ip", "sourceIp", "destinationIp"):
            val = _val(row.get(field))
            if val and val not in ("0.0.0.0", "none", "null"):
                ips.add(val)
        return ips

    ips_a = _extract_ips(a)
    ips_b = _extract_ips(b)

    same_user = user_a is not None and user_b is not None and user_a == user_b
    same_device = dev_a is not None and dev_b is not None and dev_a == dev_b
    same_ip = bool(ips_a & ips_b)

    return same_user or same_device or same_ip


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def group_by_entities(df: pd.DataFrame, window_minutes: float | None = None) -> list[pd.DataFrame]:
    """Cluster alerts into candidate incident groups via entity resolution.

    Uses union-find over all alert pairs that satisfy `_alerts_linked`
    (shared entity + within the correlation window), producing transitive
    clusters — e.g. alert A and C can end up in the same incident even
    if they share no entity directly, as long as both link to alert B.

    Alerts are processed in chronological order and, for each anchor
    alert, comparison stops as soon as a later alert falls outside the
    window (since the frame is sorted, everything after that
    point is outside the window too).

    Returns
    -------
    list[pd.DataFrame]
        One DataFrame per cluster, each holding the original alert rows
        sorted by timestamp. Groups are ordered by their earliest alert.
    """
    work = _validate_and_prepare(df)
    n = len(work)
    if n == 0:
        return []

    win = window_minutes if window_minutes is not None else TIME_WINDOW_MINUTES
    uf = _UnionFind(range(n))
    window = pd.Timedelta(minutes=win)

    for i in range(n):
        row_i = work.iloc[i]
        for j in range(i + 1, n):
            row_j = work.iloc[j]
            if (row_j["timestamp"] - row_i["timestamp"]) > window:
                break  # sorted by time -> nothing further can be in-window
            if _alerts_linked(row_i, row_j, window_minutes=win):
                uf.union(i, j)

    clusters: dict[int, list[int]] = {}
    for i in range(n):
        root = uf.find(i)
        clusters.setdefault(root, []).append(i)

    groups = [work.iloc[idxs].sort_values("timestamp") for idxs in clusters.values()]
    groups.sort(key=lambda g: g["timestamp"].min())
    return groups


def calculate_confidence(alerts: pd.DataFrame, window_minutes: float | None = None) -> int:
    """Score how strongly a group of alerts belongs together, 0-100.

    Point weights (per project spec):
        +30  same user across every alert in the group
        +25  same device across every alert in the group
        +20  same ip_address across every alert in the group
        +25  the group's time span (last - first) is within the
             correlation window

    A single-alert group trivially agrees with itself on every
    dimension and scores 100.
    """
    if alerts is None or len(alerts) == 0:
        return 0

    score = 0

    if alerts["user"].dropna().nunique() <= 1:
        score += 30

    if alerts["device"].dropna().nunique() <= 1:
        score += 25

    if alerts["ip_address"].dropna().nunique() <= 1:
        score += 20

    win = window_minutes if window_minutes is not None else TIME_WINDOW_MINUTES
    timestamps = pd.to_datetime(alerts["timestamp"], utc=True)
    span_minutes = (timestamps.max() - timestamps.min()).total_seconds() / 60.0
    if span_minutes <= win:
        score += 25

    return int(score)


def correlate_alerts(df: pd.DataFrame) -> list[dict]:
    """Main entry point: turn a raw alert DataFrame into reconstructed incidents.

    Orchestrates:
        1. group_by_entities()            -> candidate alert clusters
        2. incident_builder.build_incident -> final incident records
           (which internally calls calculate_confidence per cluster)

    Parameters
    ----------
    df : pd.DataFrame
        Raw SOC alerts with the columns listed in REQUIRED_COLUMNS.

    Returns
    -------
    list[dict]
        One dict per reconstructed incident:
            {
                "incident_id": str,
                "alerts": list[dict],
                "confidence": int,
                "first_seen": pd.Timestamp,
                "last_seen": pd.Timestamp,
                "entities": {"users": [...], "devices": [...], "ip_addresses": [...]},
            }
    """
    # Local import avoids a circular import at module load time, since
    # incident_builder also imports from this module.
    from .incident_builder import build_incident

    groups = group_by_entities(df)
    return build_incident(groups)
