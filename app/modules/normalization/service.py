from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List
import uuid

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _string(value: Any, default: str) -> str:
    text = str(value).strip() if value is not None else ""
    return text or default


def _metadata(payload: Dict[str, Any], event_metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for src in (payload.get("metadata") or {}, event_metadata or {}):
        if isinstance(src, dict):
            merged.update(deepcopy(src))
    trusted_workspace = event_metadata.get("workspace") if isinstance(event_metadata, dict) else None
    trusted_tenant = event_metadata.get("tenant") if isinstance(event_metadata, dict) else None
    workspace = trusted_workspace or payload.get("workspace") or merged.get("workspace") or merged.get("tenant") or "default"
    tenant = trusted_tenant or payload.get("tenant") or (workspace if trusted_workspace else merged.get("tenant") or workspace)
    merged["workspace"] = str(workspace)
    merged["tenant"] = str(tenant)
    merged.setdefault("ingested_from", _string(payload.get("source") or payload.get("provider"), "unknown"))
    return merged


def normalize_alert_payload(payload: Dict[str, Any], event_metadata: Dict[str, Any] | None = None) -> Dict[str, Any]:
    raw = deepcopy(payload or {})
    severity = _string(raw.get("severity"), "HIGH").upper()
    if severity not in SEVERITIES:
        severity = "HIGH"
    timestamp = raw.get("timestamp")
    if isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        timestamp = timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    timestamp = _string(timestamp, _now_iso())
    title = _string(raw.get("title") or raw.get("event_type") or raw.get("alert_type"), "Security Alert")
    technique = _string(raw.get("mitreTechnique") or raw.get("mitre_technique") or raw.get("technique") or title, title)
    technique_id = _string(raw.get("techniqueId") or raw.get("mitre_technique") or raw.get("mitreTechniqueId"), "T1059")
    category = _string(raw.get("category") or raw.get("scenario") or raw.get("mitreTactic"), "Attack Telemetry")
    metadata = _metadata(raw, event_metadata)
    return {
        "id": _string(raw.get("id") or raw.get("alert_id"), f"ALT-{uuid.uuid4().hex[:8].upper()}"),
        "alert_id": _string(raw.get("alert_id") or raw.get("id"), ""),
        "title": title,
        "severity": severity,
        "category": category,
        "sourceIp": _string(raw.get("sourceIp") or raw.get("src_ip") or raw.get("ip_address"), "0.0.0.0"),
        "destinationIp": _string(raw.get("destinationIp") or raw.get("dst_ip"), "0.0.0.0"),
        "host": _string(raw.get("host") or raw.get("device") or raw.get("hostname"), "HOST-01"),
        "user": _string(raw.get("user") or raw.get("username"), "analyst"),
        "timestamp": timestamp,
        "mitreTactic": _string(raw.get("mitreTactic") or raw.get("category") or raw.get("scenario"), category),
        "mitreTechnique": technique,
        "techniqueId": technique_id,
        "status": _string(raw.get("status"), "NEW").upper(),
        "incidentId": raw.get("incident_id") or raw.get("incidentId"),
        "confidenceScore": float(raw.get("confidenceScore") or raw.get("confidence") or 92.0),
        "source": _string(raw.get("source") or raw.get("provider"), "EDR"),
        "description": _string(raw.get("description"), title),
        "rawLog": raw.get("rawLog") or f"Telemetry: {title}",
        "metadata": metadata,
    }


def normalize_alert_batch(payloads: Iterable[Dict[str, Any]], event_metadata: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    return [normalize_alert_payload(item, event_metadata=event_metadata) for item in (payloads or [])]
