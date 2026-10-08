"""
Attack Timeline Utilities
==========================
Helpers for ordering a correlated group of alerts into a chronological
attack timeline, for use in SOC incident views and summaries.

Pure Python + pandas. No ML, no APIs, no frontend.
"""

from __future__ import annotations

import pandas as pd


def create_attack_timeline(alerts: pd.DataFrame) -> list[dict]:
    """Return alerts as a chronologically ordered list of timeline events.

    Each event dict contains all original alert fields plus:
        - "sequence": 1-based position in the ordered timeline
        - "time_since_first_seconds": seconds elapsed since the first
          event in the group

    This is what an incident's "attack progression" view is built from
    — e.g. failed_login -> privilege_escalation -> data_exfiltration.

    Parameters
    ----------
    alerts : pd.DataFrame
        Alerts belonging to a single (already-correlated) incident.

    Returns
    -------
    list[dict]
        Chronologically ordered timeline events. Empty list if `alerts`
        is empty or None.
    """
    if alerts is None or len(alerts) == 0:
        return []

    ordered = alerts.copy()
    ordered["timestamp"] = pd.to_datetime(ordered["timestamp"], utc=True)
    ordered = ordered.sort_values("timestamp").reset_index(drop=True)

    first_ts = ordered["timestamp"].iloc[0]
    events = []
    for i, row in ordered.iterrows():
        event = row.to_dict()
        event["sequence"] = i + 1
        event["time_since_first_seconds"] = (row["timestamp"] - first_ts).total_seconds()
        events.append(event)

    return events


def get_first_event(alerts: pd.DataFrame):
    """Return the timestamp of the earliest alert in the group.

    Returns None for an empty/None group.
    """
    if alerts is None or len(alerts) == 0:
        return None
    return pd.to_datetime(alerts["timestamp"], utc=True).min()


def get_last_event(alerts: pd.DataFrame):
    """Return the timestamp of the latest alert in the group.

    Returns None for an empty/None group.
    """
    if alerts is None or len(alerts) == 0:
        return None
    return pd.to_datetime(alerts["timestamp"], utc=True).max()
