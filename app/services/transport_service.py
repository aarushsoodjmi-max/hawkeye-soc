"""Tenant-scoped application services for the authenticated transport layer."""
from __future__ import annotations

import os
import hashlib
from datetime import datetime, timezone
from typing import Any

from app.repositories import repository
from app.reporting.report_generator import generate_incident_report
from app.reporting.executive_summary import create_executive_summary
from app.reporting.threat_intelligence import get_attack_chain_summary
from app.reporting.json_export import export_report

_REPORT_BASE = os.path.join(os.path.dirname(__file__), "..", "reporting", "output")


class DashboardService:
    """Canonical dashboard contract.

    Every value is derived from real persisted PostgreSQL-backed repository
    state (alerts/events, incidents, assets). Metrics for which no truthful
    backend signal exists are returned as ``None`` (frontend must render an
    explicit unavailable state, never fabricate). Semantics:

    - activeIncidents  : incidents in ACTIVE/TRIAGING/CONTAINED/ACTIVE_CONTAINMENT
    - totalAlerts      : persisted alert (event) count in the workspace
    - incidentSeverity : severity histogram over workspace incidents
    - incidentStatus   : status histogram over workspace incidents
    - eventsProcessed  : persisted event records (events and alerts share the
                         same persisted record set in this pipeline)
    - sensorSources    : distinct persisted telemetry ``source`` values; None
                         when no telemetry sources exist
    - ingestionRate    : events/sec computed from persisted event timestamps
                         within the trailing 300s backend window; None when the
                         window contains no events (insufficient telemetry)
    - mttdMinutes      : mean time to detection from persisted first-alert and
                         detected-at timestamps; None when insufficient
    - mttcMinutes      : mean time to containment from persisted detected-at
                         and containment timestamps; None when insufficient
    - bufferUtilization: None — no backend queue/buffer metric exists
    - sensorHealth     : None — no real sensor health telemetry is collected
    - generatedAt      : server clock time of this response
    """

    _WINDOW_SECONDS = 300

    @staticmethod
    def _parse_ts(value: Any):
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _mean(values: list[float]) -> float | None:
        return round(sum(values) / len(values), 2) if values else None

    def get(self, workspace: str | None = None) -> dict[str, Any]:
        incidents = repository.get_incidents(workspace=workspace)[0]
        alerts, _ = repository.get_alerts(limit=5000, offset=0, workspace=workspace)
        now = datetime.now(timezone.utc)

        severity: dict[str, int] = {}
        status: dict[str, int] = {}
        for i in incidents:
            sev = str(getattr(i, "severity", "UNKNOWN"))
            st = str(getattr(i, "status", "UNKNOWN"))
            severity[sev] = severity.get(sev, 0) + 1
            status[st] = status.get(st, 0) + 1
        active = sum(1 for i in incidents if str(getattr(i, "status", "")).upper() in {"ACTIVE", "TRIAGING", "CONTAINED", "ACTIVE_CONTAINMENT"})

        event_times = [self._parse_ts(getattr(a, "timestamp", None)) for a in alerts]
        recent = [t for t in event_times if t is not None and 0 <= (now - t).total_seconds() <= self._WINDOW_SECONDS]
        ingestion_rate = round(len(recent) / self._WINDOW_SECONDS, 2) if recent else None

        sources = sorted({str(getattr(a, "source", "") or "unknown") for a in alerts})
        sensor_sources = len(sources) if sources else None

        mttd_values: list[float] = []
        mttc_values: list[float] = []
        for inc in incidents:
            detected = self._parse_ts(getattr(inc, "detectedAt", None) or getattr(inc, "openedAt", None))
            related = [t for t in (self._parse_ts(getattr(a, "timestamp", None)) for a in alerts if getattr(a, "incidentId", None) == inc.id) if t is not None]
            if detected and related:
                d = (detected - min(related)).total_seconds() / 60.0
                if d >= 0:
                    mttd_values.append(d)
            if detected and str(getattr(inc, "status", "")).upper() in {"CONTAINED", "MITIGATED", "CLOSED", "ACTIVE_CONTAINMENT"}:
                contained = self._parse_ts(getattr(inc, "containedAt", None) or getattr(inc, "updatedAt", None))
                if contained:
                    c = (contained - detected).total_seconds() / 60.0
                    if c >= 0:
                        mttc_values.append(c)

        return {
            "activeIncidents": active,
            "totalAlerts": len(alerts),
            "incidentSeverity": severity,
            "incidentStatus": status,
            "eventsProcessed": len(alerts),
            "sensorSources": sensor_sources,
            "ingestionRate": ingestion_rate,
            "mttdMinutes": self._mean(mttd_values),
            "mttcMinutes": self._mean(mttc_values),
            "bufferUtilization": None,
            "sensorHealth": None,
            "generatedAt": now.isoformat().replace("+00:00", "Z"),
        }


class EventService:
    def list(self, limit: int = 100, workspace: str | None = None) -> list[Any]:
        alerts, _ = repository.get_alerts(limit=max(1, min(limit, 1000)), workspace=workspace)
        return alerts


class IncidentService:
    def list(self, workspace: str | None = None) -> list[Any]:
        return repository.get_incidents(workspace=workspace)[0]

    def get(self, incident_id: str, workspace: str | None = None):
        return repository.get_incident_by_id(incident_id, workspace=workspace)


class AssetService:
    def list(self, workspace: str | None = None) -> list[dict]:
        out: dict[str, dict] = {}
        for inc in repository.get_incidents(workspace=workspace)[0]:
            for asset in getattr(inc, "affectedAssets", []) or []:
                aid = str(getattr(asset, "id", ""))
                if aid:
                    out[aid] = asset.model_dump() if hasattr(asset, "model_dump") else dict(asset.__dict__)
        return list(out.values())

    def get(self, asset_id: str, workspace: str | None = None):
        return next((a for a in self.list(workspace) if str(a.get("id")) == asset_id), None)


class KnowledgeGraphService:
    def graph(self, workspace: str | None = None) -> dict:
        """Expose canonical temporal KG data, restricted to one workspace."""
        nodes: list[Any] = []
        edges: list[dict[str, Any]] = []
        for inc in repository.get_incidents(workspace=workspace)[0]:
            kg = getattr(inc, "knowledgeGraph", {}) or {}
            if kg:
                nodes.extend(kg.get("nodes", []) or [])
                for rel in kg.get("relationships", []) or []:
                    edges.append({
                        "source": rel.get("source"),
                        "target": rel.get("target"),
                        "relationship_type": rel.get("relationship_type"),
                        "valid_from": rel.get("valid_from"),
                        "valid_to": rel.get("valid_to"),
                        "confidence": float(rel["confidence"]) if rel.get("confidence") is not None else None,
                    })
            else:
                deps = getattr(inc, "assetDependencies", {}) or {}
                for src, targets in deps.items():
                    nodes.append({"id": str(src), "type": "asset"})
                    for target in targets:
                        if isinstance(target, dict):
                            edges.append({"source": str(src), "target": str(target.get("asset_id") or target.get("id")), "relationship_type": "depends_on", "valid_from": None, "valid_to": None, "confidence": float(target["confidence"]) if target.get("confidence") is not None else None})
                        else:
                            edges.append({"source": str(src), "target": str(target), "relationship_type": "depends_on", "valid_from": None, "valid_to": None, "confidence": None})
        nodes.extend(AssetService().list(workspace))
        unique_nodes: list[Any] = []
        seen: set[str] = set()
        for node in nodes:
            identifier = str(node.get("id")) if isinstance(node, dict) else str(getattr(node, "id", ""))
            if not identifier or identifier in seen:
                continue
            seen.add(identifier)
            unique_nodes.append(node)
        return {"nodes": unique_nodes, "edges": edges}

    def traverse(self, entity_id: str, depth: int = 2, workspace: str | None = None) -> dict:
        graph = self.graph(workspace)
        adj: dict[str, list[dict]] = {}
        for edge in graph["edges"]:
            adj.setdefault(str(edge["source"]), []).append(edge)
        seen = {entity_id}
        frontier = [entity_id]
        edges: list[dict] = []
        for _ in range(depth):
            nxt: list[str] = []
            for node in frontier:
                for edge in adj.get(node, []):
                    target = str(edge["target"])
                    if target not in seen:
                        seen.add(target)
                        nxt.append(target)
                        edges.append(edge)
            frontier = nxt
        return {"entity": entity_id, "depth": depth, "entities": sorted(seen), "edges": edges}


class ReportService:
    def _input(self, incident_id: str, incident: Any) -> dict[str, Any]:
        raw = incident.model_dump(by_alias=False) if hasattr(incident, "model_dump") else dict(incident)
        events = [{"timestamp": e.get("timestamp", ""), "technique": e.get("techniqueId") or e.get("technique", ""), "description": e.get("description", "")} for e in raw.get("timelineEvents", []) or []]
        entities = [f"host:{a.get('name', a.get('id', ''))}" for a in raw.get("affectedAssets", []) or []]
        root = raw.get("rootCause") or {}
        return {"incident_id": incident_id, "title": raw.get("title", "Security Incident"), "description": raw.get("description", ""), "affected_entities": entities, "events": events, "root_cause": (root.get("reasoning") or root.get("vector")) if isinstance(root, dict) else str(root), "confidence": (root.get("confidence") if isinstance(root, dict) else None)}

    def generate(self, incident_id: str, workspace: str | None = None) -> dict[str, Any] | None:
        incident = repository.get_incident_by_id(incident_id, workspace=workspace)
        if not incident:
            return None
        data = self._input(incident_id, incident)
        report = generate_incident_report(data)
        report["executive_summary"] = create_executive_summary(data)
        report["attack_chain"] = get_attack_chain_summary([e.get("technique", "") for e in data["events"]])
        return report

    def list(self, workspace: str | None = None) -> list[dict[str, Any]]:
        incidents = repository.get_incidents(workspace=workspace)[0]
        return [{"incident_id": str(getattr(i, "id", "")), "available": True} for i in incidents]

    def executive(self, incident_id: str, workspace: str | None = None) -> dict[str, Any] | None:
        incident = repository.get_incident_by_id(incident_id, workspace=workspace)
        if not incident:
            return None
        raw = incident.model_dump(by_alias=False) if hasattr(incident, "model_dump") else dict(incident)
        canonical = {
            "incident_id": incident_id,
            "workspace_id": workspace,
            "title": raw.get("title"),
            "status": raw.get("status"),
            "severity": raw.get("severity"),
            "risk": {"score": raw.get("riskScore"), "level": raw.get("riskLevel"), "breakdown": raw.get("riskBreakdown", {})},
            "business_impact": raw.get("businessImpact") or {"summary": raw.get("impactSummary"), "label": "estimated"},
            "prediction": (raw.get("predictions") or [None])[-1],
            "confidence": raw.get("confidenceAssessment") or raw.get("confidenceContract"),
            "knowledge_graph": raw.get("knowledgeGraph", {}),
            "threat_intelligence": raw.get("threatIntelligence", {}),
            "memory": raw.get("incidentMemory", {}),
            "timeline": raw.get("timelineEvents", []),
            "affected_assets": raw.get("affectedAssets", []),
            "recommended_actions": raw.get("recommendedActions", []),
        }
        executive_input = self._input(incident_id, incident)
        canonical["executive_summary"] = create_executive_summary(executive_input)
        canonical["attack_chain"] = get_attack_chain_summary([e.get("technique", "") for e in executive_input["events"]])
        canonical["data_labels"] = {
            "risk": "calculated",
            "prediction": "predicted",
            "confidence": "calculated",
            "business_impact": (raw.get("businessImpact") or {}).get("data_classification", "estimated"),
        }
        return canonical

    def export(self, incident_id: str, workspace: str | None = None) -> str | None:
        report = self.generate(incident_id, workspace=workspace)
        if not report:
            return None
        workspace_key = hashlib.sha256(str(workspace or "default").encode("utf-8")).hexdigest()[:12]
        return export_report(report, os.path.join(_REPORT_BASE, f"{workspace_key}-{incident_id}.json"))


_dashboard = DashboardService()
_events = EventService()
_incidents = IncidentService()
_assets = AssetService()
_graph = KnowledgeGraphService()
_reports = ReportService()
