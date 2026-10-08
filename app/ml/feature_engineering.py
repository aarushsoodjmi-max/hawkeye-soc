"""
HawkEye SOC — Feature Engineering
==================================
Transforms raw incident telemetry into a high-dimensional, domain-aligned numerical
feature vector consumed by the root-cause RandomForestClassifier and evaluation suite.

Features extracted include:
  • Alert volume & structural metrics (counts, log scale, multi-alert flag, unique types)
  • Severity distribution (critical/high/low counts, ratios, max & mean severity)
  • Entity scope (unique devices, users, IPs, entity density, external IP presence)
  • Threat activity indicators & frequencies (auth anomalies, script/powershell execution,
    privilege escalation, credential access, data exfiltration, malware, phishing, C2/lateral)
  • Kill-chain dynamics (first-stage indicator, distinct stage breadth, incident duration)
  • Telemetry sensor distribution (EDR, Email Gateway, Active Directory, SIEM, Network, DLP)

All public helpers return either a pd.DataFrame (batch) or a dict (single incident).
"""

from __future__ import annotations

import logging
from typing import Any, Union
import ipaddress
import numpy as np
import pandas as pd

log = logging.getLogger("hawkeye.features")

# ---------------------------------------------------------------------------
# Threat Domain Keywords (Comprehensive mapping across MITRE ATT&CK & SOC telemetry)
# ---------------------------------------------------------------------------

AUTH_KEYWORDS: list[str] = [
    "login_anomaly", "failed login", "anomalous login", "impossible travel",
    "mfa bypass", "failed authentication", "after-hours access", "badge/login mismatch",
    "unauthorized mailbox access", "new access token", "t1110", "t1078", "t1111", "t1550", "ad",
]

SCRIPT_KEYWORDS: list[str] = [
    "powershell", "powershell_exec", "script", "ps1", "macro execution",
    "suspicious process", "child process", "cmd.exe", "winword", "encodedcommand",
    "invoke-expression", "invoke-", "bypass", "stager", "reflective", "t1059", "t1204",
]

PRIVILEGE_KEYWORDS: list[str] = [
    "privilege_escalation", "privilege use", "elevated", "escalation",
    "shadow copy", "vssadmin", "backup service disabled", "disabled security",
    "account access revoked", "account disabled", "sudo", "root",
    "t1078.004", "t1490", "t1489", "t1562", "t1531",
]

CREDENTIAL_KEYWORDS: list[str] = [
    "credential_dump", "credential access", "lsass", "procdump", "mimikatz",
    "dumping", "kerberoast", "token", "rubeus", "t1003", "t1555",
]

DATA_KEYWORDS: list[str] = [
    "data_access", "sensitive file", "bulk download", "removable media",
    "personal cloud upload", "data staging", "exfiltration", "print spike",
    "archive file", "mass file modification", "file extension change",
    "database query", "s3", "t1005", "t1030", "t1052", "t1567", "t1074", "t1486",
]

MALWARE_KEYWORDS: list[str] = [
    "malware_detected", "file dropped", "av detection", "process injection",
    "registry persistence", "scheduled task created", "malware", "trojan",
    "ransomware", "ransom note", "quarantined", "isolated", "known malware family",
    "initial access artifact", "lateral encryption", "dll injection",
    "t1105", "t1055", "t1547", "t1053", "t1486", "t1491", "t1588",
]

PHISHING_KEYWORDS: list[str] = [
    "phishing_email", "phishing", "url click", "credential harvesting",
    "attachment opened", "fake login", "email reported", "sandbox detonation",
    "spear", "malicious link", "email attachment", "t1566",
]

CREDENTIAL_DUMP_KEYWORDS: list[str] = [
    "credential dumping", "credential dump", "lsass", "mimikatz", "procdump",
    "rubeus", "kerberoast", "t1003",
]
EXFILTRATION_KEYWORDS: list[str] = [
    "exfiltration", "exfiltrate", "cloud upload", "personal cloud",
    "bulk download", "data staging", "removable media", "large data transfer",
    "t1567", "t1074", "t1052",
]
SHADOW_COPY_KEYWORDS: list[str] = [
    "shadow copy", "vssadmin", "volume shadow", "t1490",
]
RANSOMWARE_KEYWORDS: list[str] = [
    "ransomware", "ransom note", "mass file modification", "file extension change",
    "lateral encryption", "encryption key exchange", "t1486", "t1491",
]

NETWORK_KEYWORDS: list[str] = [
    "outbound_connection", "outbound c2", "beacon", "dns anomaly",
    "network scan", "lateral spread", "lateral movement", "c2", "port scan",
    "t1071", "t1046", "t1021",
]

SEVERITY_ORDER: dict[str, int] = {
    "info":     0,
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}

# ---------------------------------------------------------------------------
# Canonical Feature Column Registry
# ---------------------------------------------------------------------------

FEATURE_COLUMNS: list[str] = [
    # Volume & Structure
    "alert_count",
    "is_multi_alert",
    "log_alert_count",
    "unique_alert_types",
    "distinct_stages",
    "duration_minutes",

    # Severity distribution
    "critical_count",
    "high_count",
    "critical_ratio",
    "high_ratio",
    "high_or_critical_ratio",
    "low_ratio",
    "max_severity",
    "mean_severity",

    # Entity scope & density
    "unique_users",
    "unique_devices",
    "unique_ips",
    "alerts_per_device",
    "alerts_per_user",
    "has_repeated_user",
    "has_repeated_device",
    "has_external_ip",

    # Threat activity indicators & ratios
    "auth_anomaly_count",
    "auth_anomaly_ratio",
    "script_exec_count",
    "script_exec_ratio",
    "privilege_count",
    "privilege_ratio",
    "credential_access_count",
    "credential_access_ratio",
    "data_access_count",
    "data_access_ratio",
    "malware_count",
    "malware_ratio",
    "phishing_count",
    "phishing_ratio",
    "network_c2_count",
    "network_c2_ratio",

    # Temporal & Sensor context
    "first_is_phish",
    "first_is_auth",
    "first_is_malw",
    "first_is_script",
    "source_edr_ratio",
    "source_email_ratio",
    "source_ad_ratio",
    "source_siem_ratio",
    "source_network_ratio",
    "source_dlp_ratio",
]

# Legacy feature alias mappings for backwards compatibility
_LEGACY_ALIASES: dict[str, str] = {
    "critical_alerts": "critical_count",
    "powershell_present": "script_exec_count",
    "privilege_present": "privilege_count",
    "phishing_present": "phishing_count",
    "data_access_present": "data_access_count",
    "severity_numeric": "max_severity",
    "high_severity_ratio": "high_or_critical_ratio",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _is_external_ip(ip: Any) -> bool:
    """Return True only for globally routable IP addresses."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return addr.is_global


def _match_keywords(text: str, keywords: list[str]) -> bool:
    """Return True if any keyword is present in text."""
    lowered = str(text).lower()
    return any(k in lowered for k in keywords)


def _severity_to_int(severity: Any) -> int:
    """Convert severity name to integer rank 0-4."""
    return SEVERITY_ORDER.get(str(severity).strip().lower(), 1)


# ---------------------------------------------------------------------------
# Unified Feature Extraction & Aggregation
# ---------------------------------------------------------------------------

def aggregate_incident_features(events: Union[pd.DataFrame, list[dict], dict]) -> dict[str, float]:
    """
    Authoritative single-source feature extractor and aggregator.
    Used identically by batch training, model evaluation, and real-time inference.
    """
    if isinstance(events, dict):
        # If the dict is already a pre-aggregated feature dict, normalize and fill
        if any(c in events for c in ("alert_count", "unique_devices", "script_exec_count", "powershell_present")):
            row: dict[str, float] = {}
            for c in FEATURE_COLUMNS:
                if c in events:
                    row[c] = float(events[c])
                else:
                    # Check legacy aliases
                    found = False
                    for leg_key, canon_key in _LEGACY_ALIASES.items():
                        if canon_key == c and leg_key in events:
                            row[c] = float(events[leg_key])
                            found = True
                            break
                    if not found:
                        row[c] = 0.0
            return row
        df = pd.DataFrame([events])
    elif isinstance(events, list):
        if not events:
            return {c: 0.0 for c in FEATURE_COLUMNS}
        df = pd.DataFrame(events)
    elif isinstance(events, pd.DataFrame):
        if events.empty:
            return {c: 0.0 for c in FEATURE_COLUMNS}
        df = events.copy()
    else:
        return {c: 0.0 for c in FEATURE_COLUMNS}

    # Normalize column names across various schemas
    col_map: dict[str, str] = {}
    for col in df.columns:
        clow = str(col).lower().strip()
        if clow in ("username", "user_name", "usr"):
            col_map[col] = "user"
        elif clow in ("hostname", "host", "device_name"):
            col_map[col] = "device"
        elif clow in ("src_ip", "source_ip", "sourceip", "ip"):
            if "ip_address" not in col_map.values() and "ip_address" not in df.columns:
                col_map[col] = "ip_address"
        elif clow in ("dst_ip", "destination_ip", "destinationip", "dest_ip"):
            col_map[col] = "destination_ip"
        elif clow in ("event_type", "title", "name"):
            col_map[col] = "alert_type"
        elif clow in ("sev",):
            col_map[col] = "severity"
        elif clow in ("desc", "detail"):
            col_map[col] = "description"

    if col_map:
        df = df.rename(columns=col_map)

    n = len(df)
    if n == 0:
        return {c: 0.0 for c in FEATURE_COLUMNS}

    # Ensure required columns
    if "alert_type" not in df.columns:
        df["alert_type"] = ""
    if "severity" not in df.columns:
        df["severity"] = "low"
    if "description" not in df.columns:
        df["description"] = ""
    if "source" not in df.columns:
        df["source"] = ""
    if "device" not in df.columns:
        df["device"] = "unknown_device"
    if "user" not in df.columns:
        df["user"] = "unknown_user"
    if "ip_address" not in df.columns:
        df["ip_address"] = "0.0.0.0"

    # Parse timestamps for sequence and duration
    if "timestamp" in df.columns:
        ts_data = df["timestamp"]
        if isinstance(ts_data, pd.DataFrame):
            ts_data = ts_data.iloc[:, 0]
        try:
            df["_ts"] = pd.to_datetime(ts_data, errors="coerce", utc=True)
            df = df.sort_values("_ts")
        except Exception:
            df["_ts"] = pd.NaT

    types = df["alert_type"].astype(str).tolist()
    sources = df["source"].astype(str).str.lower().tolist()
    sevs = df["severity"].astype(str).str.lower().tolist()
    descs = df["description"].astype(str).tolist()
    combos = [f"{t} {d}".lower() for t, d in zip(types, descs)]

    # Activity count matches
    auth_cnt = sum(1 for c in combos if _match_keywords(c, AUTH_KEYWORDS))
    script_cnt = sum(1 for c in combos if _match_keywords(c, SCRIPT_KEYWORDS))
    priv_cnt = sum(1 for c in combos if _match_keywords(c, PRIVILEGE_KEYWORDS))
    cred_cnt = sum(1 for c in combos if _match_keywords(c, CREDENTIAL_KEYWORDS))
    data_cnt = sum(1 for c in combos if _match_keywords(c, DATA_KEYWORDS))
    malw_cnt = sum(1 for c in combos if _match_keywords(c, MALWARE_KEYWORDS))
    phish_cnt = sum(1 for c in combos if _match_keywords(c, PHISHING_KEYWORDS))
    net_cnt = sum(1 for c in combos if _match_keywords(c, NETWORK_KEYWORDS))
    credential_dump_cnt = sum(1 for c in combos if _match_keywords(c, CREDENTIAL_DUMP_KEYWORDS))
    exfiltration_cnt = sum(1 for c in combos if _match_keywords(c, EXFILTRATION_KEYWORDS))
    shadow_copy_cnt = sum(1 for c in combos if _match_keywords(c, SHADOW_COPY_KEYWORDS))
    ransomware_cnt = sum(1 for c in combos if _match_keywords(c, RANSOMWARE_KEYWORDS))

    # Severity analysis
    sev_nums = [_severity_to_int(s) for s in sevs]
    crit_cnt = sum(1 for s in sevs if s == "critical")
    high_cnt = sum(1 for s in sevs if s == "high")
    low_cnt = sum(1 for s in sevs if s in ("low", "info"))

    # Entity analysis
    u_users = df["user"].dropna().nunique() or 1
    u_devs = df["device"].dropna().nunique() or 1
    u_ips = df["ip_address"].dropna().nunique() or 1

    has_ext_ip = float(any(_is_external_ip(ip) for ip in df["ip_address"].dropna()))
    if "destination_ip" in df.columns:
        has_ext_ip = float(has_ext_ip or any(_is_external_ip(ip) for ip in df["destination_ip"].dropna()))

    # Duration calculation
    dur_min = 0.0
    if "_ts" in df.columns:
        valid_ts = df["_ts"].dropna()
        if len(valid_ts) >= 2:
            try:
                dur_min = max(0.0, float((valid_ts.max() - valid_ts.min()).total_seconds() / 60.0))
            except Exception:
                dur_min = 0.0

    # Initial stage indicator
    first_c = combos[0] if combos else ""
    first_is_phish = float(_match_keywords(first_c, PHISHING_KEYWORDS))
    first_is_auth = float(_match_keywords(first_c, AUTH_KEYWORDS))
    first_is_malw = float(_match_keywords(first_c, MALWARE_KEYWORDS))
    first_is_script = float(_match_keywords(first_c, SCRIPT_KEYWORDS))

    # Distinct stages
    distinct_stages = sum(
        1 for cnt in (auth_cnt, script_cnt, priv_cnt, cred_cnt, data_cnt, malw_cnt, phish_cnt, net_cnt)
        if cnt > 0
    )

    # Sensor breakdown
    edr_cnt = sum(1 for s in sources if "edr" in s)
    email_cnt = sum(1 for s in sources if "email" in s or "gateway" in s)
    ad_cnt = sum(1 for s in sources if "ad" in s or "directory" in s)
    siem_cnt = sum(1 for s in sources if "siem" in s)
    net_src_cnt = sum(1 for s in sources if any(k in s for k in ("firewall", "proxy", "ids", "netflow")))
    dlp_cnt = sum(1 for s in sources if "dlp" in s)

    return {
        # Volume & Structure
        "alert_count": float(n),
        "is_multi_alert": float(1.0 if n > 1 else 0.0),
        "log_alert_count": float(np.log1p(n)),
        "unique_alert_types": float(df["alert_type"].nunique() or 1),
        "distinct_stages": float(distinct_stages),
        "duration_minutes": float(dur_min),

        # Severity
        "critical_count": float(crit_cnt),
        "high_count": float(high_cnt),
        "critical_ratio": float(crit_cnt / n),
        "high_ratio": float(high_cnt / n),
        "high_or_critical_ratio": float((crit_cnt + high_cnt) / n),
        "low_ratio": float(low_cnt / n),
        "max_severity": float(max(sev_nums) if sev_nums else 1),
        "mean_severity": float(np.mean(sev_nums) if sev_nums else 1.0),

        # Scope
        "unique_users": float(u_users),
        "unique_devices": float(u_devs),
        "unique_ips": float(u_ips),
        "alerts_per_device": float(n / max(1, u_devs)),
        "alerts_per_user": float(n / max(1, u_users)),
        "has_repeated_user": float(1.0 if n > u_users else 0.0),
        "has_repeated_device": float(1.0 if n > u_devs else 0.0),
        "has_external_ip": float(has_ext_ip),

        # Threat counts & ratios
        "auth_anomaly_count": float(auth_cnt),
        "auth_anomaly_ratio": float(auth_cnt / n),
        "script_exec_count": float(script_cnt),
        "script_exec_ratio": float(script_cnt / n),
        "privilege_count": float(priv_cnt),
        "privilege_ratio": float(priv_cnt / n),
        "credential_access_count": float(cred_cnt),
        "credential_access_ratio": float(cred_cnt / n),
        "data_access_count": float(data_cnt),
        "data_access_ratio": float(data_cnt / n),
        "malware_count": float(malw_cnt),
        "malware_ratio": float(malw_cnt / n),
        "phishing_count": float(phish_cnt),
        "phishing_ratio": float(phish_cnt / n),
        "network_c2_count": float(net_cnt),
        "network_c2_ratio": float(net_cnt / n),
        # Evidence indicators retained for deterministic detection/root-cause
        # fallback. The pinned ML model simply ignores these extra columns.
        "credential_dump_count": float(credential_dump_cnt),
        "exfiltration_count": float(exfiltration_cnt),
        "shadow_copy_count": float(shadow_copy_cnt),
        "ransomware_count": float(ransomware_cnt),

        # Temporal & Sensor
        "first_is_phish": float(first_is_phish),
        "first_is_auth": float(first_is_auth),
        "first_is_malw": float(first_is_malw),
        "first_is_script": float(first_is_script),
        "source_edr_ratio": float(edr_cnt / n),
        "source_email_ratio": float(email_cnt / n),
        "source_ad_ratio": float(ad_cnt / n),
        "source_siem_ratio": float(siem_cnt / n),
        "source_network_ratio": float(net_src_cnt / n),
        "source_dlp_ratio": float(dlp_cnt / n),
    }


def extract_features_from_dict(incident: dict) -> dict[str, float]:
    """Build a feature dict from a single incident record or dictionary."""
    return aggregate_incident_features(incident)


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transform raw incident CSV DataFrame into a model-ready feature matrix.
    Aggregates per incident_id and preserves the ground-truth root_cause label.
    """
    df = df.copy()
    if "incident_id" not in df.columns:
        df["incident_id"] = [f"INC-{i}" for i in range(len(df))]

    rows = []
    for inc_id, group in df.groupby("incident_id", sort=False):
        feat = aggregate_incident_features(group)
        feat["incident_id"] = inc_id
        if "root_cause" in group.columns:
            rc = group["root_cause"].dropna()
            feat["root_cause"] = rc.iloc[0] if not rc.empty else "benign"
        rows.append(feat)

    res = pd.DataFrame(rows)
    feature_cols = [c for c in FEATURE_COLUMNS if c in res.columns]
    extra_cols = [c for c in res.columns if c not in FEATURE_COLUMNS]
    return res[feature_cols + extra_cols]


def build_feature_row(incident: Union[dict, list[dict], pd.DataFrame]) -> pd.DataFrame:
    """
    Wrap aggregate_incident_features into a single-row DataFrame aligned with FEATURE_COLUMNS.
    Input format consumed by the trained scikit-learn model.
    """
    features = aggregate_incident_features(incident)
    row = {col: features.get(col, 0.0) for col in FEATURE_COLUMNS}
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)
