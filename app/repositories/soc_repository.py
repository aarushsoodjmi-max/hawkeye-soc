"""
HawkEye SOC — SOC Repository & Pipeline Coordinator
===================================================
Coordinates the full security operations lifecycle:
simulator → ingestion → correlation → incident building → ML root cause → risk scoring → frontend.

Tenant enforcement
------------------
The repository is the single data-access choke point for every HawkEye
module. All reads/mutations are workspace-scoped: a request can only reach
incidents/alerts that belong to its canonical workspace (derived from the
verified token in ``app.core.auth`` and never from client-supplied values).
Pure simulator/bootstrap flows without a tenant context operate on the
default workspace, preserving existing public APIs.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from app.config import settings
from app.schemas import (
    ActionStatusType,
    AffectedAsset,
    AiAnalysisResult,
    Alert,
    AlertStatusType,
    Incident,
    IncidentStatusType,
    KpiMetrics,
    RecommendedAction,
    RootCause,
    SeverityType,
    TimelineEvent,
)

# Internal pipeline modules
from app.correlation.correlation_engine import (
    calculate_confidence,
    group_by_entities,
)
from app.correlation.timeline import create_attack_timeline
from app.ml.predictor import load_model, safe_predict_root_cause
from app.ml.feature_engineering import aggregate_incident_features
from app.analytics.risk_scoring import calculate_risk_score
from app.analytics.explainability import explain_incident, generate_explanation
from app.simulator.attack_simulator import AttackSimulator
from app.core.event_bus import event_bus
from app.core.auth import Principal
from app.db import PersistentStateRepository
from app.core.audit import audit_log
from app.core.observability import incident_id as incident_id_var, event_id as event_id_var, execution_id as execution_id_var
import hashlib
import json

log = logging.getLogger("hawkeye.repository")


class ActionApprovalError(RuntimeError):
    """Raised when an operational action violates the approval invariant."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


_DEFAULT_WORKSPACE = "default"


def _forward_publish(topic: str, payload: dict[str, Any], workspace: str | None) -> None:
    """Durably enqueue then publish through the existing in-process EventBus."""
    payload = dict(payload) if payload else {}
    ws = workspace or _DEFAULT_WORKSPACE
    payload.setdefault("workspace", ws)
    event_id = f"{topic}:{uuid.uuid4().hex}"
    payload.setdefault("event_id", event_id)
    tok = event_id_var.set(event_id)
    try:
        store = PersistentStateRepository()
        # QUEUED is intentionally retained until the canonical subscriber
        # confirms successful processing. EventBus enqueue is not delivery.
        store.queue_dispatch(ws, event_id, topic, payload)
        try:
            event_bus.publish_nowait(topic, payload)
        except Exception:
            # The durable row remains QUEUED for bounded startup recovery.
            raise
    finally:
        event_id_var.reset(tok)


class SocRepository:
    """Thread-safe repository and pipeline runner for HawkEye SOC."""

    def __init__(self):
        self._lock = threading.RLock()
        self._persistent = PersistentStateRepository()
        self.alerts: List[Alert] = []
        self.incidents: Dict[str, Incident] = {}
        # Tenant index: entity id -> {"kind": ..., "workspace": ...}. Every
        # Alert/Incident ever stored is bound to exactly one workspace.
        self._index: Dict[str, Dict[str, str]] = {}
        self._init_prewarm_ml()
        self._load_or_seed_persistent_state()

    def _load_or_seed_persistent_state(self) -> None:
        """Restore durable canonical state, or seed the demo baseline once."""
        stored_alerts = self._persistent.list_all("events")
        stored_incidents = self._persistent.list_all("incidents")
        if stored_alerts or stored_incidents:
            self.alerts.clear(); self.incidents.clear(); self._index.clear()
            for ws, aid, payload in stored_alerts:
                try:
                    alert = Alert.model_validate(payload)
                except Exception:
                    continue
                self.alerts.append(alert); self._index[f"{ws}:{alert.id}"] = {"kind": "Alert", "workspace": ws}
                if ws == _DEFAULT_WORKSPACE:
                    self._index[str(alert.id)] = {"kind": "Alert", "workspace": ws}
            for ws, iid, payload in stored_incidents:
                try:
                    incident = Incident.model_validate(payload)
                except Exception:
                    continue
                incident.metadata.setdefault("workspace", ws); incident.metadata.setdefault("workspace_id", ws)
                key = str(incident.id) if ws == _DEFAULT_WORKSPACE else f"{ws}:{incident.id}"
                self.incidents[key] = incident; self._index[f"{ws}:{incident.id}"] = {"kind": "Incident", "workspace": ws}
                if ws == _DEFAULT_WORKSPACE:
                    self._index[str(incident.id)] = {"kind": "Incident", "workspace": ws}
            self._hydrate_repository_incidents(reason="restart_restore")
        else:
            # Never seed merely because the configured database is empty. Demo
            # data enters through the explicit seed_demo_data() operation.
            self.alerts.clear()
            self.incidents.clear()
            self._index.clear()

    def seed_demo_data(self, workspace: str = _DEFAULT_WORKSPACE) -> None:
        """Explicitly persist the demo baseline into the configured database."""
        if not settings.DEMO_MODE:
            raise RuntimeError("Demo seeding requires DEMO_MODE=true")
        if workspace != _DEFAULT_WORKSPACE:
            raise RuntimeError("The built-in demo baseline is only defined for the default workspace")
        with self._lock:
            if self.incidents or self.alerts:
                return
            self._seed_baseline_data()
            for alert in self.alerts:
                self._persist_alert(alert, workspace)
            for incident in self.incidents.values():
                self._persist_incident(incident, workspace)
            self._hydrate_repository_incidents(reason="explicit_demo_seed")

    @staticmethod
    def _json_model(value: Any) -> dict:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        return dict(value) if isinstance(value, dict) else {"value": value}

    def _persist_alert(self, alert: Alert, workspace: str) -> None:
        payload = self._json_model(alert)
        fingerprint_payload = {"id": str(alert.id), "title": alert.title, "timestamp": alert.timestamp, "host": alert.host, "user": alert.user, "source": alert.source or "EDR", "rawLog": alert.rawLog or f"Telemetry: {alert.title} on {alert.host} by {alert.user}"}
        fingerprint = hashlib.sha256(json.dumps(fingerprint_payload, sort_keys=True, default=str).encode()).hexdigest()
        inserted = self._persistent.insert_event(workspace, str(alert.id), payload, fingerprint)
        if not inserted:
            self._persistent.update_event(workspace, str(alert.id), payload)
        self._persistent.upsert_normalized_event(workspace, str(alert.id), payload)

    def _persist_incident(self, incident: Incident, workspace: str) -> None:
        payload = self._json_model(incident)
        self._persistent.upsert("incidents", workspace, str(incident.id), payload)
        # Persist canonical intelligence surfaces as durable snapshots.
        surfaces = {
            "knowledge_graph": incident.knowledgeGraph, "threat_intelligence": incident.threatIntelligence,
            "risk": {"riskScore": incident.riskScore, "riskLevel": incident.riskLevel, "riskBreakdown": incident.riskBreakdown},
            "prediction": incident.predictions[-1] if incident.predictions else {},
            "confidence": incident.confidenceAssessment or incident.confidenceContract,
            "decisions": incident.decisionRecommendations or incident.lastDecision,
            "simulations": incident.latestSimulation, "playbooks": incident.lastApprovedPlaybook,
        }
        for kind, value in surfaces.items():
            if value:
                self._persistent.upsert(kind, workspace, str(incident.id), {"incident_id": str(incident.id), "workspace_id": workspace, "data": self._json_model(value) if not isinstance(value, dict) else value})
        for asset in incident.affectedAssets or []:
            self._persistent.upsert("assets", workspace, str(asset.id), self._json_model(asset))
        for event in incident.timelineEvents or []:
            self._persistent.upsert("entities", workspace, f"{incident.id}:{event.id}", self._json_model(event))

    def _hydrate_repository_incidents(self, reason: str = "periodic_baseline") -> None:
        """Canonical single hydration point: any repository instance populates the
        canonical intelligence surfaces for every incident it owns."""
        from app.modules.incidents.service import hydrate_incident_intelligence

        for incident in list(self.incidents.values()):
            try:
                incident.alerts = [a for a in self.alerts if a.incidentId == incident.id]
                hydrate_incident_intelligence(incident, snapshot_reason=reason, workspace_id=self._workspace_for(incident))
            except Exception as exc:  # pragma: no cover - defensive bootstrap path
                log.warning("Failed to hydrate incident %s: %s", incident.id, exc)

    # -----------------------------------------------------------------------
    # Tenant helpers
    # -----------------------------------------------------------------------
    def _ws(self, workspace: Optional[str] = None) -> str:
        return workspace or _DEFAULT_WORKSPACE

    def _bind(self, entity: Any, workspace: Optional[str] = None) -> Any:
        """Bind an entity to a workspace without allowing same IDs to collide."""
        ws = self._ws(workspace)
        eid = getattr(entity, "id", None) or getattr(entity, "incident_id", None)
        if eid:
            self._index[f"{ws}:{eid}"] = {"kind": type(entity).__name__, "workspace": ws}
            if ws == _DEFAULT_WORKSPACE:
                self._index[str(eid)] = {"kind": type(entity).__name__, "workspace": ws}
            metadata = getattr(entity, "metadata", None)
            if isinstance(metadata, dict):
                metadata.setdefault("workspace", ws); metadata.setdefault("workspace_id", ws)
        return entity

    def _workspace_for(self, entity: Any) -> str:
        metadata = getattr(entity, "metadata", None)
        if isinstance(metadata, dict) and (metadata.get("workspace_id") or metadata.get("workspace")):
            return str(metadata.get("workspace_id") or metadata.get("workspace"))
        eid = getattr(entity, "id", None) or getattr(entity, "incident_id", None)
        if eid:
            return self._index.get(str(eid), {}).get("workspace", _DEFAULT_WORKSPACE)
        return _DEFAULT_WORKSPACE

    def _publish_event(self, topic: str, payload: dict[str, Any], workspace: Optional[str] = None) -> None:
        """Publish with the canonical workspace inferred from the request/entity."""
        payload = dict(payload or {})
        effective = workspace or payload.get("workspace")
        if not effective:
            entity_id = payload.get("incident_id") or payload.get("alert_id")
            if entity_id:
                effective = self._index.get(str(entity_id), {}).get("workspace")
        _forward_publish(topic, payload, self._ws(effective))

    def _init_prewarm_ml(self):
        """Load and pre-warm the configured scikit-learn root cause model."""
        configured = Path(settings.MODEL_PATH).expanduser()
        if not configured.is_absolute():
            configured = (Path(__file__).resolve().parent.parent / configured).resolve()
        model_path = configured
        try:
            load_model(model_path)
            log.info("ML root cause model pre-warmed from %s", model_path)
        except Exception as exc:
            # ML is advisory. A missing/incompatible artifact must never prevent
            # telemetry injection from reaching correlation and persistence.
            log.warning("Could not pre-warm ML model from %s: %s", model_path, type(exc).__name__)

    # -----------------------------------------------------------------------
    # Baseline Data Seeding
    # -----------------------------------------------------------------------
    def _seed_baseline_data(self):
        """Seed realistic baseline incidents and alerts representing active campaigns."""
        with self._lock:
            # --- Incident 1: INC-8942 (Kerberoasting & Lateral Movement) ---
            inc_1_id = "INC-8942"
            now = datetime.now(timezone.utc)
            inc_1_time = now.strftime("%Y-%m-%d %H:%M:%S UTC")

            inc_1_assets = [
                AffectedAsset(
                    id="AST-01",
                    name="WS-FINANCE-04",
                    ip="10.240.12.84",
                    os="Windows 11 Enterprise (Build 22631)",
                    role="Dev Workstation",
                    status="COMPROMISED",
                    criticality="TIER 2",
                ),
                AffectedAsset(
                    id="AST-02",
                    name="DC-PRIMARY-01",
                    ip="10.240.10.10",
                    os="Windows Server 2022 Datacenter",
                    role="Domain Controller",
                    status="COMPROMISED",
                    criticality="TIER 0",
                ),
                AffectedAsset(
                    id="AST-03",
                    name="VPN-EDGE-WEST",
                    ip="198.51.100.24",
                    os="PAN-OS 10.2.7-h3",
                    role="API Gateway",
                    status="ISOLATED",
                    criticality="TIER 1",
                ),
            ]

            inc_1_root_cause = RootCause(
                vector="Unauthenticated Arbitrary File Creation Leading to Remote Code Execution",
                cveId="CVE-2024-3400",
                cveScore=10.0,
                entryPoint="Edge VPN Gateway (VPN-EDGE-WEST:443)",
                compromisedAccount="svc_backup_admin (Active Directory Service Principal)",
                c2Server="185.220.101.5:443 (dnsc2tunnel[.]xyz)",
                c2Location="St. Petersburg, Russian Federation (AS49447)",
                vulnerabilityDetails="Exploitation of command injection vulnerability in GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges.",
                detectionMechanism="HawkEye Neural Correlation Engine (Correlation Matrix Score: 98.4%)",
                initialPayload="/tmp/session_verify.py -> cobaltstrike_beacon.bin (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)",
                firstObserved="2026-09-03 04:18:22 UTC",
                primary="compromised_account",
                confidence=0.984,
                confidence_status="ML-supported root cause",
                confidenceStatus="ML-supported root cause",
                requires_analyst_verification=False,
                requiresAnalystVerification=False,
                reasoning="Compromised credentials combined with CVE-2024-3400 perimeter exploit enabled domain-wide Kerberoasting and LSASS dumping.",
                contributingFactors=[
                    "Unpatched edge gateway (CVE-2024-3400)",
                    "Weak RC4 encryption on service ticket",
                    "Over-privileged service account",
                ],
            )

            inc_1_actions = [
                RecommendedAction(
                    id="ACT-01",
                    title="Isolate Compromised Host: WS-FINANCE-04",
                    description="Trigger EDR network quarantine via API. Terminate active sessions and sever lateral SMB channels while keeping telemetry link open.",
                    type="CONTAINMENT",
                    status="PENDING",
                    target="WS-FINANCE-04 (10.240.12.84)",
                    riskLevel="HIGH",
                    playbookId="PB-CONTAIN-001",
                ),
                RecommendedAction(
                    id="ACT-02",
                    title="Rotate Kerberos Ticket Granting Service Account (KRBTGT)",
                    description="Initiate double password reset on the primary Active Directory KRBTGT account to invalidate forged Golden and Silver Tickets.",
                    type="CONTAINMENT",
                    status="PENDING",
                    target="DC-PRIMARY-01 (Domain: CORP.DEFENSE.MIL)",
                    riskLevel="HIGH",
                    playbookId="PB-AD-004",
                ),
                RecommendedAction(
                    id="ACT-03",
                    title="Block Known Adversary C2 Infrastructure on Border Firewalls",
                    description="Push automated border firewall ACL to drop all ingress and egress traffic targeting 185.220.101.5 and DNS blackhole dnsc2tunnel[.]xyz.",
                    type="CONTAINMENT",
                    status="COMPLETED",
                    target="Border Palo Alto Cluster & Umbrella DNS",
                    riskLevel="LOW",
                    executedAt="2026-09-03 04:45:12 UTC",
                    executedBy="SOAR Auto-Playbook Orchestrator",
                    playbookId="PB-NET-012",
                ),
                RecommendedAction(
                    id="ACT-04",
                    title="Force Immediate Credential Invalidation for svc_backup_admin",
                    description="Revoke all Kerberos TGTs, reset NT password hash, and disable Interactive Logon rights for compromised service account.",
                    type="ERADICATION",
                    status="PENDING",
                    target="svc_backup_admin",
                    riskLevel="MED",
                    playbookId="PB-IAM-008",
                ),
            ]

            inc_1_timeline = [
                TimelineEvent(
                    id="EVT-01",
                    timestamp="04:18:22 UTC",
                    relativeTime="+00:00:00",
                    tactic="Initial Access",
                    technique="Exploit Public-Facing Application",
                    techniqueId="T1190",
                    title="CVE-2024-3400 Exploitation on Border VPN",
                    description="Attacker exploited unpatched PAN-OS RCE vulnerability via GlobalProtect HTTP POST payload.",
                    source="Palo Alto Traps / Perimeter Firewall",
                    target="VPN-EDGE-WEST (198.51.100.24)",
                    severity="CRITICAL",
                    command="curl -k -H 'Cookie: SESSID=../../../../tmp/session_verify.py' https://198.51.100.24/ssl-vpn/hipreport.esp",
                    ioc={"type": "IP", "value": "185.220.101.5"},
                    evidenceConfidence=98.5,
                    phaseOrder=1,
                ),
                TimelineEvent(
                    id="EVT-02",
                    timestamp="04:22:10 UTC",
                    relativeTime="+00:03:48",
                    tactic="Execution",
                    technique="Command and Scripting Interpreter: PowerShell",
                    techniqueId="T1059.001",
                    title="Obfuscated PowerShell Stager Execution",
                    description="Attacker downloaded reflective Cobalt Strike DLL loader via base64 encoded PowerShell process.",
                    source="CrowdStrike Falcon Sensor (PID: 6184)",
                    target="WS-FINANCE-04 (10.240.12.84)",
                    severity="HIGH",
                    command="powershell.exe -noni -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt...",
                    ioc={"type": "HASH", "value": "8b1a9953c4611296a827abf8c47804d7"},
                    evidenceConfidence=96.0,
                    phaseOrder=2,
                ),
                TimelineEvent(
                    id="EVT-03",
                    timestamp="04:27:45 UTC",
                    relativeTime="+00:09:23",
                    tactic="Command and Control",
                    technique="Application Layer Protocol: Web Protocols",
                    techniqueId="T1071.001",
                    title="Cobalt Strike Malleable C2 Beacon Established",
                    description="Outbound TLS beaconing initiated to AS49447 over TCP/443 with 30-second jitter intervals.",
                    source="Zeek Network Security Monitor / Core Bro",
                    target="185.220.101.5:443",
                    severity="CRITICAL",
                    ioc={"type": "DOMAIN", "value": "dnsc2tunnel[.]xyz"},
                    evidenceConfidence=94.2,
                    phaseOrder=3,
                ),
                TimelineEvent(
                    id="EVT-04",
                    timestamp="04:31:02 UTC",
                    relativeTime="+00:12:40",
                    tactic="Credential Access",
                    technique="Steal or Forge Kerberos Tickets: Kerberoasting",
                    techniqueId="T1558.003",
                    title="Kerberoasting Request for Service Account TGS",
                    description="Attacker queried Active Directory for SPNs registered with weak RC4 encryption to crack svc_backup_admin password offline.",
                    source="Active Directory Event ID 4769",
                    target="DC-PRIMARY-01 (10.240.10.10)",
                    severity="CRITICAL",
                    command="Rubeus.exe kerberoast /outfile:hashes.kerberoast /nowrap /rc4opsec",
                    evidenceConfidence=97.8,
                    phaseOrder=4,
                ),
                TimelineEvent(
                    id="EVT-05",
                    timestamp="04:35:19 UTC",
                    relativeTime="+00:16:57",
                    tactic="Privilege Escalation",
                    technique="Access Token Manipulation",
                    techniqueId="T1134.001",
                    title="Token Impersonation to SYSTEM",
                    description="Attacker escalated privileges to NT AUTHORITY\\SYSTEM by duplicating backup service token.",
                    source="Sysmon Event ID 1 / Windows Defender ATP",
                    target="WS-FINANCE-04",
                    severity="HIGH",
                    command="Incognito.exe list_tokens -u && Incognito.exe execute -c 'NT AUTHORITY\\SYSTEM' cmd.exe",
                    evidenceConfidence=92.5,
                    phaseOrder=5,
                ),
                TimelineEvent(
                    id="EVT-06",
                    timestamp="04:39:50 UTC",
                    relativeTime="+00:21:28",
                    tactic="Credential Access",
                    technique="OS Credential Dumping: LSASS Memory",
                    techniqueId="T1003.001",
                    title="ProcDump Memory Extraction on Domain Controller",
                    description="Attacker executed Sysinternals ProcDump against LSASS process on the Primary Domain Controller via SMB Admin share.",
                    source="EDR Behavioral Engine (PDC01-AGENT)",
                    target="DC-PRIMARY-01 (10.240.10.10)",
                    severity="CRITICAL",
                    command="procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass_dmp.bin",
                    ioc={"type": "PAYLOAD", "value": "lsass_dmp.bin"},
                    evidenceConfidence=99.1,
                    phaseOrder=6,
                ),
                TimelineEvent(
                    id="EVT-07",
                    timestamp="04:43:08 UTC",
                    relativeTime="+00:24:46",
                    tactic="Exfiltration",
                    technique="Exfiltration Over Alternative Protocol: Symmetric Encrypted Archive",
                    techniqueId="T1048.003",
                    title="Staged Archive Staging for C2 Exfiltration",
                    description="Multi-part AES-256 archive created containing scraped domain credentials, prepared for outbound transmission.",
                    source="SentinelOne Endpoint Deep Visibility",
                    target="DC-PRIMARY-01 -> 185.220.101.5",
                    severity="HIGH",
                    command="7z.exe a -p'SecK3y99!' -mhe=on -v50m C:\\Users\\Public\\dc_data.7z C:\\Windows\\Temp\\*.bin",
                    evidenceConfidence=91.0,
                    phaseOrder=7,
                ),
            ]

            inc_1_ai = AiAnalysisResult(
                analyzedAt="2026-09-03 04:45:00 UTC",
                confidenceScore=98.4,
                threatClassification="APT29 / Nobelium - Verified Active Directory Kerberoast Hegemony Vector",
                mitreCoverage=["T1190", "T1059.001", "T1071.001", "T1558.003", "T1134.001", "T1003.001", "T1048.003"],
                keyFindings=[
                    "Confirmed zero-trust perimeter breach via CVE-2024-3400 arbitrary file creation on VPN-EDGE-WEST.",
                    "Extracted Cobalt Strike 4.9 beacon configuration indicates fallback C2 DNS channel on dnsc2tunnel[.]xyz.",
                    "High-privilege Kerberos service ticket hash cracked in under 34 minutes due to weak RC4 ticket encryption policy.",
                    "ProcDump memory artifact on DC-PRIMARY-01 isolated; zero NTDS.dit SAM database credentials leaked externally.",
                ],
                killChainStage="Stage 6 (Lateral Containment Phase)",
                blastRadius="Contained to 2 internal endpoints and 1 boundary gateway; zero tenant cloud infrastructure touched.",
                urgency="IMMEDIATE",
                suggestedContainmentSteps=[
                    "Enforce Host Quarantining on WS-FINANCE-04 (10.240.12.84) immediately.",
                    "Execute dual KRBTGT password rotation across Domain Controllers.",
                    "Block C2 IP 185.220.101.5 and DNS domain dnsc2tunnel[.]xyz in Palo Alto WAF.",
                    "Audit all recent Kerberos service ticket issuances in last 12 hours.",
                ],
                summary="Deep neural correlation completed across 7 raw telemetry events, 4 EDR alerts, and 3 network flows. Root cause definitively traced to unauthenticated GlobalProtect command injection. Containment playbooks have been queued.",
            )

            self.incidents[inc_1_id] = Incident(
                id=inc_1_id,
                incident_id=inc_1_id,
                title="INC-8942: Kerberoasting & Lateral Movement toward Primary Domain Controller",
                severity="CRITICAL",
                status="ACTIVE",
                threatActor="APT29 (Cozy Bear / Nobelium)",
                threatActorOrigin="Russian Foreign Intelligence Service (SVR)",
                detectedAt="2026-09-03 04:18:22 UTC",
                updatedAt="2026-09-03 04:45:12 UTC",
                leadAnalyst="Alexander Reyes (Lead)",
                impactSummary="Unauthenticated Palo Alto VPN command injection (CVE-2024-3400) escalated into domain controller LSASS credential dumping. Attacker actively staging ransomware / exfiltration tunnel.",
                affectedAssets=inc_1_assets,
                rootCause=inc_1_root_cause,
                recommendedActions=inc_1_actions,
                timelineEvents=inc_1_timeline,
                aiAnalysis=inc_1_ai,
                associatedAlertCount=7,
                riskScore=95,
                riskLevel="CRITICAL",
                riskBreakdown={
                    "criticalAlert": True,
                    "privilegeEscalation": True,
                    "dataAccess": True,
                    "multipleDevices": True,
                    "multipleIps": False,
                },
            )

            # --- Incident 2: INC-8939 (Cloud IAM Privilege Escalation) ---
            inc_2_id = "INC-8939"
            self.incidents[inc_2_id] = Incident(
                id=inc_2_id,
                incident_id=inc_2_id,
                title="INC-8939: Cloud IAM Privilege Escalation & S3 Data Exfiltration",
                severity="HIGH",
                status="TRIAGING",
                threatActor="Scattered Spider (UNC3944)",
                threatActorOrigin="FIN / Cybercrime Syndicate",
                detectedAt="2026-09-02 21:05:14 UTC",
                updatedAt="2026-09-02 22:40:00 UTC",
                leadAnalyst="Maya Lin (Tier 2)",
                impactSummary="Compromised temporary AWS credentials used to attach AdministratorAccess policy to IAM role and sync sensitive customer financial buckets.",
                affectedAssets=[
                    AffectedAsset(
                        id="AST-04",
                        name="aws-iam-role-finops",
                        ip="172.31.44.12",
                        os="Amazon Linux 2023",
                        role="Cloud IAM",
                        status="MONITORED",
                        criticality="TIER 1",
                    ),
                    AffectedAsset(
                        id="AST-05",
                        name="s3-prod-customer-ledger",
                        ip="52.216.14.88",
                        os="AWS S3 Multi-Region",
                        role="Production DB",
                        status="COMPROMISED",
                        criticality="TIER 0",
                    ),
                ],
                rootCause=RootCause(
                    vector="Exposed IAM Session Token in Public Git Repository",
                    entryPoint="Public GitHub commit artifact",
                    compromisedAccount="aws_deployer_bot",
                    c2Server="Tor Exit Node (185.220.100.252)",
                    c2Location="Amsterdam, Netherlands",
                    vulnerabilityDetails="Developers committed hardcoded AWS STS temporary token to public repository.",
                    detectionMechanism="AWS GuardDuty UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
                    initialPayload="aws sts get-caller-identity",
                    firstObserved="2026-09-02 21:05:14 UTC",
                    primary="compromised_account",
                    confidence=0.912,
                    confidence_status="ML-supported root cause",
                    confidenceStatus="ML-supported root cause",
                    requires_analyst_verification=False,
                    requiresAnalystVerification=False,
                    reasoning="Credentials used from unverified Tor exit relay to enumerate permissions and sync S3 buckets.",
                    contributingFactors=["Hardcoded cloud credentials", "Lack of Git secret scanning pre-commit hook"],
                ),
                recommendedActions=[
                    RecommendedAction(
                        id="ACT-05",
                        title="Revoke Active AWS IAM Role Sessions",
                        description="Attach inline deny-all policy to aws-iam-role-finops with condition on CurrentTime to invalidate all active STS sessions.",
                        type="CONTAINMENT",
                        status="COMPLETED",
                        target="aws-iam-role-finops",
                        riskLevel="HIGH",
                        executedAt="2026-09-02 21:30:00 UTC",
                        executedBy="Maya Lin (Tier 2)",
                        playbookId="PB-CLOUD-002",
                    ),
                    RecommendedAction(
                        id="ACT-06",
                        title="Block Tor Exit Nodes in AWS WAF & VPC NACL",
                        description="Sync Tor exit node IP blacklists into perimeter AWS Network Firewall and WAF ip-sets.",
                        type="HARDENING",
                        status="PENDING",
                        target="AWS Network Firewall",
                        riskLevel="LOW",
                        playbookId="PB-NET-015",
                    ),
                ],
                timelineEvents=[
                    TimelineEvent(
                        id="EVT-08",
                        timestamp="21:05:14 UTC",
                        relativeTime="+00:00:00",
                        tactic="Credential Access",
                        technique="Credentials from Password Stores",
                        techniqueId="T1555",
                        title="Leaked AWS STS Token Used from Tor Relay",
                        description="Attacker queried STS API to verify permissions.",
                        source="AWS CloudTrail",
                        target="aws_deployer_bot",
                        severity="CRITICAL",
                        command="aws sts get-caller-identity",
                        ioc={"type": "IP", "value": "185.220.100.252"},
                        evidenceConfidence=99.0,
                        phaseOrder=1,
                    ),
                    TimelineEvent(
                        id="EVT-09",
                        timestamp="21:14:30 UTC",
                        relativeTime="+00:09:16",
                        tactic="Privilege Escalation",
                        technique="Cloud Infrastructure: Modify IAM Policy",
                        techniqueId="T1098",
                        title="AdministratorAccess Policy Attached to Role",
                        description="Attacker invoked iam:AttachRolePolicy to grant administrative privileges.",
                        source="AWS CloudTrail",
                        target="aws-iam-role-finops",
                        severity="HIGH",
                        command="aws iam attach-role-policy --role-name aws-iam-role-finops --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                        evidenceConfidence=98.0,
                        phaseOrder=2,
                    ),
                ],
                aiAnalysis=AiAnalysisResult(
                    analyzedAt="2026-09-02 21:40:00 UTC",
                    confidenceScore=93.5,
                    threatClassification="Scattered Spider - Cloud Credential Harvesting Campaign",
                    mitreCoverage=["T1555", "T1098", "T1567.002"],
                    keyFindings=[
                        "STS token leaked via commit to public GitHub repository.",
                        "Direct administrative policy attachment detected within 9 minutes of first use.",
                        "Active sessions revoked; data sync halted.",
                    ],
                    killChainStage="Stage 4 (Privilege Escalation)",
                    blastRadius="Contained to 1 AWS IAM role and 1 S3 bucket.",
                    urgency="HIGH",
                    suggestedContainmentSteps=[
                        "Revoke STS sessions",
                        "Rotate parent IAM user credentials",
                        "Audit AWS S3 access logs",
                    ],
                    summary="Cloud privilege escalation detected via leaked credentials. Response playbooks executed to revoke sessions.",
                ),
                associatedAlertCount=4,
                riskScore=75,
                riskLevel="HIGH",
                riskBreakdown={
                    "criticalAlert": False,
                    "privilegeEscalation": True,
                    "dataAccess": True,
                    "multipleDevices": False,
                    "multipleIps": True,
                },
            )

            # Seed initial telemetry alerts matching the incidents
            baseline_alerts = [
                Alert(
                    id="ALT-1001",
                    alert_id="ALT-1001",
                    title="CVE-2024-3400 Remote Code Execution Payload",
                    severity="CRITICAL",
                    category="Initial Access",
                    sourceIp="185.220.101.5",
                    destinationIp="198.51.100.24",
                    host="VPN-EDGE-WEST",
                    user="admin",
                    timestamp="2026-09-03T04:18:22Z",
                    mitreTactic="Initial Access",
                    mitreTechnique="Exploit Public-Facing Application",
                    techniqueId="T1190",
                    status="CONTAINED",
                    incidentId=inc_1_id,
                    confidenceScore=98.5,
                    source="Palo Alto WAF",
                    description="Unauthenticated arbitrary file creation on GlobalProtect endpoint.",
                    rawLog="POST /ssl-vpn/hipreport.esp HTTP/1.1 200 OK Host: 198.51.100.24 Cookie: SESSID=../../../../tmp/session_verify.py",
                ),
                Alert(
                    id="ALT-1002",
                    alert_id="ALT-1002",
                    title="Cobalt Strike Beacon Ingress / PowerShell Stager",
                    severity="HIGH",
                    category="Execution",
                    sourceIp="185.220.101.5",
                    destinationIp="10.240.12.84",
                    host="WS-FINANCE-04",
                    user="j.smith",
                    timestamp="2026-09-03T04:22:10Z",
                    mitreTactic="Execution",
                    mitreTechnique="PowerShell",
                    techniqueId="T1059.001",
                    status="INVESTIGATING",
                    incidentId=inc_1_id,
                    confidenceScore=96.0,
                    source="CrowdStrike EDR",
                    description="Obfuscated base64 PowerShell invocation downloading reflective DLL.",
                    rawLog="powershell.exe -noni -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt...",
                ),
                Alert(
                    id="ALT-1003",
                    alert_id="ALT-1003",
                    title="Outbound C2 Beaconing to dnsc2tunnel[.]xyz",
                    severity="CRITICAL",
                    category="Command and Control",
                    sourceIp="10.240.12.84",
                    destinationIp="185.220.101.5",
                    host="WS-FINANCE-04",
                    user="j.smith",
                    timestamp="2026-09-03T04:27:45Z",
                    mitreTactic="Command and Control",
                    mitreTechnique="Application Layer Protocol",
                    techniqueId="T1071.001",
                    status="INVESTIGATING",
                    incidentId=inc_1_id,
                    confidenceScore=94.2,
                    source="Zeek Network Monitor",
                    description="Periodic TLS beacons on port 443 with 30s jitter.",
                    rawLog="TLS session established with SNI: dnsc2tunnel.xyz cipher: TLS_AES_256_GCM_SHA384",
                ),
                Alert(
                    id="ALT-1004",
                    alert_id="ALT-1004",
                    title="Kerberoasting Request (TGS 0x17 RC4)",
                    severity="CRITICAL",
                    category="Credential Access",
                    sourceIp="10.240.12.84",
                    destinationIp="10.240.10.10",
                    host="DC-PRIMARY-01",
                    user="svc_backup_admin",
                    timestamp="2026-09-03T04:31:02Z",
                    mitreTactic="Credential Access",
                    mitreTechnique="Kerberoasting",
                    techniqueId="T1558.003",
                    status="INVESTIGATING",
                    incidentId=inc_1_id,
                    confidenceScore=97.8,
                    source="Active Directory Security Log",
                    description="Event ID 4769 - Kerberos service ticket was requested with RC4 encryption.",
                    rawLog="EventID: 4769 TargetUserName: svc_backup_admin TicketEncryptionType: 0x17 FailureCode: 0x0",
                ),
                Alert(
                    id="ALT-1005",
                    alert_id="ALT-1005",
                    title="ProcDump Memory Scraping on LSASS Process",
                    severity="CRITICAL",
                    category="Credential Access",
                    sourceIp="10.240.12.84",
                    destinationIp="10.240.10.10",
                    host="DC-PRIMARY-01",
                    user="svc_backup_admin",
                    timestamp="2026-09-03T04:39:50Z",
                    mitreTactic="Credential Access",
                    mitreTechnique="LSASS Memory",
                    techniqueId="T1003.001",
                    status="INVESTIGATING",
                    incidentId=inc_1_id,
                    confidenceScore=99.1,
                    source="Sysmon Event 10",
                    description="Process procdump64.exe opened handle to lsass.exe with PROCESS_VM_READ permissions.",
                    rawLog="procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass_dmp.bin",
                ),
                Alert(
                    id="ALT-1006",
                    alert_id="ALT-1006",
                    title="AWS IAM Token Used from Tor Relay",
                    severity="HIGH",
                    category="Credential Access",
                    sourceIp="185.220.100.252",
                    destinationIp="52.216.14.88",
                    host="aws-iam-role-finops",
                    user="aws_deployer_bot",
                    timestamp="2026-09-02T21:05:14Z",
                    mitreTactic="Credential Access",
                    mitreTechnique="Credentials from Password Stores",
                    techniqueId="T1555",
                    status="RESOLVED",
                    incidentId=inc_2_id,
                    confidenceScore=99.0,
                    source="AWS CloudTrail",
                    description="API call GetCallerIdentity originated from known Tor exit IP.",
                    rawLog="userAgent: aws-cli/2.15.1 sourceIPAddress: 185.220.100.252 eventName: GetCallerIdentity",
                ),
                Alert(
                    id="ALT-1007",
                    alert_id="ALT-1007",
                    title="IAM Policy Escalation: AdministratorAccess Attached",
                    severity="HIGH",
                    category="Privilege Escalation",
                    sourceIp="185.220.100.252",
                    destinationIp="52.216.14.88",
                    host="aws-iam-role-finops",
                    user="aws_deployer_bot",
                    timestamp="2026-09-02T21:14:30Z",
                    mitreTactic="Privilege Escalation",
                    mitreTechnique="Modify IAM Policy",
                    techniqueId="T1098",
                    status="RESOLVED",
                    incidentId=inc_2_id,
                    confidenceScore=98.0,
                    source="AWS CloudTrail",
                    description="AttachRolePolicy invoked on role aws-iam-role-finops.",
                    rawLog="eventName: AttachRolePolicy policyArn: arn:aws:iam::aws:policy/AdministratorAccess",
                ),
            ]

            for a in baseline_alerts:
                self.alerts.append(a)

            # Bind baseline records to the default workspace (keeps the
            # existing public API fully operational without a tenant context).
            for _inc_key in (inc_1_id, inc_2_id):
                if _inc_key in self.incidents:
                    self._bind(self.incidents[_inc_key], _DEFAULT_WORKSPACE)
            for _a in self.alerts:
                self._index[str(_a.id)] = {"kind": "Alert", "workspace": _DEFAULT_WORKSPACE}

    # -----------------------------------------------------------------------
    # Ingestion & Correlation Flow
    # simulator → ingestion → correlation → incident → ML → risk → store
    # -----------------------------------------------------------------------
    def ingest_alerts(
        self,
        raw_alerts: List[Dict[str, Any]],
        scenario_hint: Optional[str] = None,
        workspace: Optional[str] = None,
    ) -> Tuple[List[Alert], Optional[str]]:
        """
        Ingests a batch of alerts and runs the complete correlation pipeline:
        1. Ingest raw alerts & normalize to canonical schema
        2. Group into candidate incidents via causal entity resolution & time window
        3. Feature engineering & ML root cause prediction
        4. Risk scoring & explainability narrative generation
        5. Assemble canonical Incident and persist to store

        ``workspace`` is derived from the authenticated principal by the
        routes; ingested alerts and any correlated incident are immediately
        bound to that canonical workspace.
        """
        with self._lock:
            ws = self._ws(workspace)
            ingested_alerts: List[Alert] = []
            now_iso = _now_iso()

            # Normalization
            for item in raw_alerts:
                alert_id = str(item.get("alert_id") or item.get("id") or f"ALT-{uuid.uuid4().hex[:6].upper()}")
                user = str(item.get("user") or item.get("username") or "analyst")
                host = str(item.get("device") or item.get("hostname") or item.get("host") or "HOST-01")
                src_ip = str(item.get("src_ip") or item.get("ip_address") or item.get("sourceIp") or "10.0.0.1")
                dst_ip = str(item.get("dst_ip") or item.get("destinationIp") or "10.0.0.2")
                title = str(item.get("title") or item.get("event_type") or item.get("alert_type") or "Security Alert")
                sev = str(item.get("severity") or "HIGH").upper()
                if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    sev = "HIGH"

                ts_val = item.get("timestamp") or now_iso
                if isinstance(ts_val, datetime):
                    if ts_val.tzinfo is None:
                        ts_val = ts_val.replace(tzinfo=timezone.utc)
                    ts_str = ts_val.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                else:
                    ts_str = str(ts_val)

                tech_id = str(item.get("mitre_technique") or item.get("techniqueId") or "T1059")
                category = str(item.get("category") or item.get("scenario") or "Attack Telemetry")
                desc = str(item.get("description") or title)

                fingerprint_payload = {
                    "id": alert_id, "title": title, "timestamp": ts_str, "host": host, "user": user,
                    "source": str(item.get("source") or "EDR"), "rawLog": item.get("rawLog") or f"Telemetry: {title} on {host} by {user}",
                }
                event_fingerprint = hashlib.sha256(json.dumps(fingerprint_payload, sort_keys=True, default=str).encode()).hexdigest()
                if self._persistent.event_exists(ws, event_fingerprint):
                    existing = self.get_alert_by_id(alert_id, workspace=ws)
                    if existing:
                        ingested_alerts.append(existing)
                    continue

                canonical_alert = Alert(
                    id=alert_id,
                    alert_id=alert_id,
                    title=title,
                    severity=sev,
                    category=category,
                    sourceIp=src_ip,
                    destinationIp=dst_ip,
                    host=host,
                    user=user,
                    timestamp=ts_str,
                    mitreTactic=category,
                    mitreTechnique=title,
                    techniqueId=tech_id,
                    status="NEW",
                    incidentId=item.get("incident_id"),
                    confidenceScore=float(item.get("confidenceScore") or 92.0),
                    source=str(item.get("source") or "EDR"),
                    description=desc,
                    rawLog=item.get("rawLog") or f"Telemetry: {title} on {host} by {user}",
                )

                self.alerts.insert(0, canonical_alert)
                self._bind(canonical_alert, ws)
                ingested_alerts.append(canonical_alert)
                # The canonical wrapper publishes event.normalized exactly once
                # after normalization metadata is attached and persistence is complete.

            # Run Correlation against incoming and relevant existing alerts
            target_incident_id = None
            if ingested_alerts:
                # 1. Identify relevant existing alerts to correlate against
                incoming_users = {
                    a.user.lower() for a in ingested_alerts
                    if a.user and a.user.lower() not in ("unknown", "unknown_user", "none")
                }
                incoming_hosts = {
                    a.host.lower() for a in ingested_alerts
                    if a.host and a.host.lower() not in ("unknown", "unknown_device", "none")
                }
                incoming_ips = {
                    ip.lower() for a in ingested_alerts
                    for ip in (a.sourceIp, a.destinationIp)
                    if ip and ip.lower() not in ("0.0.0.0", "none", "null", "unknown")
                }

                incoming_times = []
                for a in ingested_alerts:
                    try:
                        incoming_times.append(pd.to_datetime(a.timestamp, utc=True))
                    except Exception:
                        pass
                min_in_ts = min(incoming_times) if incoming_times else None
                max_in_ts = max(incoming_times) if incoming_times else None
                window_delta = pd.Timedelta(minutes=30)

                relevant_existing_alerts: List[Alert] = []
                new_ids_set = {a.id for a in ingested_alerts}
                for ex in self.alerts:
                    if ex.id in new_ids_set:
                        continue
                    # Tenant isolation: never correlate against alerts that
                    # belong to another workspace.
                    if self._workspace_for(ex) != ws:
                        continue
                    has_entity = (
                        (ex.user and ex.user.lower() in incoming_users) or
                        (ex.host and ex.host.lower() in incoming_hosts) or
                        (ex.sourceIp and ex.sourceIp.lower() in incoming_ips) or
                        (ex.destinationIp and ex.destinationIp.lower() in incoming_ips)
                    )
                    if not has_entity:
                        continue

                    if min_in_ts and max_in_ts and ex.timestamp:
                        try:
                            ex_ts = pd.to_datetime(ex.timestamp, utc=True)
                            if not ((min_in_ts - window_delta) <= ex_ts <= (max_in_ts + window_delta)):
                                continue
                        except Exception:
                            pass

                    relevant_existing_alerts.append(ex)
                    if len(relevant_existing_alerts) >= 50:
                        break

                all_candidate_alerts = ingested_alerts + relevant_existing_alerts

                # Prepare pandas DataFrame for correlation engine
                df_rows = []
                for a in all_candidate_alerts:
                    # Never use "INC-SIM" or shared dummy ID before correlation
                    real_inc_id = a.incidentId if (a.incidentId and not a.incidentId.startswith("INC-SIM")) else None
                    df_rows.append({
                        "alert_id": a.id,
                        "timestamp": a.timestamp,
                        "user": a.user,
                        "device": a.host,
                        "ip_address": a.sourceIp,
                        "destination_ip": a.destinationIp,
                        "alert_type": a.title,
                        "severity": a.severity.lower() if a.severity else "low",
                        "source": a.source or "EDR",
                        "root_cause": None,
                        "incident_id": real_inc_id,
                    })

                alerts_df = pd.DataFrame(df_rows)
                try:
                    clusters = group_by_entities(alerts_df)
                except Exception as e:
                    log.warning("Correlation grouping fallback: %s", e)
                    clusters = [alerts_df]

                candidate_map = {a.id: a for a in all_candidate_alerts}
                cluster_incident_ids: List[str] = []

                # Correlate per cluster: assign incidentId ONLY to alerts in that cluster
                for cluster in clusters:
                    cluster_alert_ids = set(cluster["alert_id"].dropna().astype(str).unique()) if "alert_id" in cluster.columns else set()
                    cluster_new_alerts = [a for a in ingested_alerts if a.id in cluster_alert_ids]
                    if not cluster_new_alerts:
                        continue

                    cluster_all_alerts = [candidate_map[aid] for aid in cluster_alert_ids if aid in candidate_map]

                    # Check if cluster links to an existing incident in self.incidents
                    existing_inc_id = None
                    for a in cluster_all_alerts:
                        candidate_key = a.incidentId if ws == _DEFAULT_WORKSPACE else f"{ws}:{a.incidentId}"
                        if a.id not in new_ids_set and a.incidentId and candidate_key in self.incidents:
                            existing_inc_id = a.incidentId
                            break

                    if existing_inc_id:
                        self._update_incident_with_cluster(
                            existing_inc_id, cluster, cluster_new_alerts, cluster_all_alerts, scenario_hint, ws
                        )
                        cluster_incident_ids.append(existing_inc_id)
                    else:
                        inc_id = self._build_incident_from_cluster(
                            cluster, cluster_all_alerts, scenario_hint, ws
                        )
                        cluster_incident_ids.append(inc_id)

                target_incident_id = cluster_incident_ids[0] if cluster_incident_ids else None

            return ingested_alerts, target_incident_id

    def _update_incident_with_cluster(
        self,
        incident_id: str,
        cluster: pd.DataFrame,
        cluster_new_alerts: List[Alert],
        cluster_all_alerts: List[Alert],
        scenario_hint: Optional[str] = None,
        workspace: Optional[str] = None,
    ):
        """Updates an existing incident with newly correlated alerts belonging to this cluster."""
        with self._lock:
            ws = self._ws(workspace)
            key = incident_id if ws == _DEFAULT_WORKSPACE else f"{ws}:{incident_id}"
            inc = self.incidents.get(key)
            if not inc:
                return
            if self._workspace_for(inc) != ws:
                return

            cluster_alert_ids = set(cluster["alert_id"].dropna().astype(str).unique()) if "alert_id" in cluster.columns else set()

            # Assign incidentId ONLY to alerts in this cluster
            for a in cluster_new_alerts:
                if a.id in cluster_alert_ids:
                    a.incidentId = incident_id
                    for stored_a in self.alerts:
                        if stored_a.id == a.id:
                            stored_a.incidentId = incident_id

            # Append new timeline events preserving real detection evidence
            existing_event_titles = {e.title.lower() for e in inc.timelineEvents}
            start_idx = len(inc.timelineEvents)
            for i, a in enumerate(cluster_new_alerts):
                if a.title.lower() in existing_event_titles:
                    continue
                sev_upper = a.severity.upper() if a.severity else "HIGH"
                if sev_upper not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    sev_upper = "HIGH"

                evt = TimelineEvent(
                    id=f"EVT-{incident_id}-{start_idx + i + 1:02d}",
                    timestamp=a.timestamp,
                    relativeTime=f"+00:{(start_idx + i)*3:02d}:00",
                    tactic=a.mitreTactic or a.category or "Execution",
                    technique=a.mitreTechnique or a.title,
                    techniqueId=a.techniqueId or "T1059",
                    title=a.title,
                    description=a.description or f"Observed on host {a.host} by user {a.user}.",
                    source=a.source or "EDR",
                    target=a.host or "Unknown",
                    severity=sev_upper,
                    evidenceConfidence=a.confidenceScore or 92.0,
                    phaseOrder=start_idx + i + 1,
                )
                inc.timelineEvents.append(evt)

            # Re-run feature aggregation using aggregate_incident_features
            event_dicts = [
                {
                    "alert_type": f"{e.title} {e.technique or ''}",
                    "severity": e.severity.lower(),
                    "device": e.target,
                    "ip_address": e.ioc.get("value") if (e.ioc and e.ioc.get("type") == "IP") else None,
                    "timestamp": e.timestamp,
                }
                for e in inc.timelineEvents
            ]
            features = aggregate_incident_features(event_dicts)

            # Re-score risk using calculate_risk_score reading risk_score / risk_level
            try:
                risk_res = calculate_risk_score({
                    "alerts": [{"severity": e.severity.lower(), "alert_type": e.title} for e in inc.timelineEvents],
                    "devices": [a.name for a in inc.affectedAssets],
                    "ips": [e.ioc.get("value") for e in inc.timelineEvents if e.ioc and e.ioc.get("type") == "IP"],
                    "techniques": [e.techniqueId for e in inc.timelineEvents if e.techniqueId],
                    "incident_id": incident_id,
                })
                inc.riskScore = risk_res.get("risk_score", inc.riskScore or 85)
                inc.riskLevel = str(risk_res.get("risk_level", inc.riskLevel or "HIGH")).upper()
            except Exception:
                pass

            inc.associatedAlertCount = len(inc.timelineEvents)
            inc.updatedAt = _now_iso()
            log.info("Correlated and updated existing incident %s with %d new alerts", incident_id, len(cluster_new_alerts))
            self._publish_event("incident.updated", {"incident_id": incident_id, "status": inc.status, "alert_count": inc.associatedAlertCount})
            self._publish_event("risk.updated", {"incident_id": incident_id, "risk_score": inc.riskScore, "risk_level": inc.riskLevel})

    def _build_incident_from_cluster(
        self,
        cluster: pd.DataFrame,
        alert_objs: List[Alert],
        scenario_hint: Optional[str] = None,
        workspace: Optional[str] = None,
    ) -> str:
        """Runs ML inference, risk scoring, explainability, and builds canonical Incident."""
        with self._lock:
            ws = self._ws(workspace)
            # Mint incident ID
            inc_num = len(self.incidents) + 8950
            incident_id = f"INC-{inc_num}"

            # 1. Authoritative Feature Engineering for ML Root Cause Predictor
            features = aggregate_incident_features(cluster)
            critical_count = int(features.get("critical_count", features.get("critical_alerts", 0)) or 0)
            alert_count = int(features.get("alert_count", len(cluster)))
            powershell_present = int(features.get("script_exec_count", features.get("powershell_present", 0)) or 0)
            privilege_present = int(features.get("privilege_count", features.get("privilege_present", 0)) or 0)
            data_access_present = int(features.get("data_access_count", features.get("data_access_present", 0)) or 0)
            unique_hosts = cluster["device"].dropna().unique().tolist() if "device" in cluster.columns else []
            unique_ips = cluster["ip_address"].dropna().unique().tolist() if "ip_address" in cluster.columns else []
            unique_destination_ips = cluster["destination_ip"].dropna().unique().tolist() if "destination_ip" in cluster.columns else []
            unique_users = cluster["user"].dropna().unique().tolist() if "user" in cluster.columns else []

            # 2. ML Root Cause Prediction
            ml_result = safe_predict_root_cause(features)
            predicted_cause = ml_result.get("root_cause")
            if not predicted_cause:
                predicted_cause = "unclassified"
            confidence = float(ml_result.get("confidence") or 0.0)
            confidence_status = ml_result.get("confidence_status") or (
                "ML-supported root cause" if confidence >= 0.70 else "Low-confidence ML prediction"
            )
            requires_verification = bool(ml_result.get("requires_analyst_verification", confidence < 0.70))

            # 3. Rule-Based Risk Scoring (analytics/risk_scoring.py)
            incident_dict_for_scoring = {
                "alerts": cluster.to_dict(orient="records"),
                "devices": unique_hosts,
                "ips": unique_ips,
                "techniques": (
                    cluster["alert_type"].dropna().tolist()
                    if "alert_type" in cluster.columns
                    else (
                        cluster["event_type"].dropna().tolist()
                        if "event_type" in cluster.columns
                        else []
                    )
                ),
                "incident_id": incident_id,
            }
            try:
                risk_res = calculate_risk_score(incident_dict_for_scoring)
                risk_score = risk_res.get("risk_score")
                risk_level = str(risk_res.get("risk_level") or "UNKNOWN").upper()
            except Exception as e:
                log.error("Risk scoring failed while creating incident %s: %s", incident_id, type(e).__name__)
                raise RuntimeError("Risk scoring service unavailable") from e

            # 4. Explainability & Kill-Chain Narrative (analytics/explainability.py)
            try:
                if "alert_type" in cluster.columns:
                    tech_list = cluster["alert_type"].dropna().tolist()
                elif "event_type" in cluster.columns:
                    tech_list = cluster["event_type"].dropna().tolist()
                else:
                    tech_list = []
                if "mitre_technique" in cluster.columns:
                    tech_list += [t for t in cluster["mitre_technique"].dropna().tolist() if t]
                narrative_res = explain_incident({"incident_id": incident_id, "techniques": tech_list})
                narrative_text = narrative_res.get("narrative")
                if not narrative_text:
                    raise RuntimeError("Explainability service returned no narrative")
                detected = narrative_res.get("detected_stages") or []
                kill_chain_stage = detected[-1].replace("_", " ").title() if detected else "Not available"
            except Exception as e:
                log.error("Explainability generation failed while creating incident %s: %s", incident_id, type(e).__name__)
                raise RuntimeError("Explainability service unavailable") from e

            # 5. Build Timeline Events preserving real alert telemetry and MITRE data
            alert_map = {a.id: a for a in alert_objs}
            sorted_cluster = cluster.copy()
            sorted_cluster["ts_parsed"] = pd.to_datetime(sorted_cluster["timestamp"], errors="coerce", utc=True)
            sorted_cluster = sorted_cluster.sort_values("ts_parsed").reset_index(drop=True)
            first_ts = sorted_cluster["ts_parsed"].iloc[0] if not sorted_cluster.empty else pd.Timestamp.now(tz="UTC")

            timeline_events: List[TimelineEvent] = []
            for i, (_, row) in enumerate(sorted_cluster.iterrows()):
                aid = str(row.get("alert_id") or "")
                alert = alert_map.get(aid)

                # Real elapsed relative time
                row_ts = row.get("ts_parsed")
                if pd.notna(row_ts) and pd.notna(first_ts):
                    delta_sec = max(0, int((row_ts - first_ts).total_seconds()))
                    rel_time = f"+{delta_sec//3600:02d}:{(delta_sec%3600)//60:02d}:{delta_sec%60:02d}"
                else:
                    rel_time = "N/A"

                # Real alert attributes; avoid fabricated IDs
                tactic = (alert.mitreTactic if alert and alert.mitreTactic else None) or (alert.category if alert and alert.category else None) or "Not available"
                technique = (alert.mitreTechnique if alert and alert.mitreTechnique else None) or str(row.get("alert_type") or "Not available")
                tech_id = alert.techniqueId if alert and alert.techniqueId else None
                title = (alert.title if alert and alert.title else None) or str(row.get("alert_type") or "Not available")
                desc = (alert.description if alert and alert.description else None) or "No description supplied by telemetry."
                source = (alert.source if alert and alert.source else None) or str(row.get("source") or "Not available")
                target = (alert.host if alert and alert.host else None) or str(row.get("device") or "Not available")

                sev_upper = str(row.get("severity", "HIGH")).upper()
                if sev_upper not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    sev_upper = "HIGH"

                evt = TimelineEvent(
                    id=f"EVT-{incident_id}-{i+1:02d}",
                    timestamp=str(row["timestamp"]),
                    relativeTime=rel_time,
                    tactic=tactic,
                    technique=technique,
                    techniqueId=tech_id,
                    title=title,
                    description=desc,
                    source=source,
                    target=target,
                    severity=sev_upper,
                    evidenceConfidence=float(alert.confidenceScore) if alert and alert.confidenceScore is not None else None,
                    phaseOrder=i + 1,
                )
                timeline_events.append(evt)

            # 6. Build Affected Assets
            affected_assets: List[AffectedAsset] = []
            for idx, host in enumerate(unique_hosts[:4]):
                ip = unique_ips[idx] if idx < len(unique_ips) else "Not available"
                affected_assets.append(
                    AffectedAsset(
                        id=f"AST-{incident_id}-{idx+1:02d}",
                        name=host,
                        ip=ip,
                        os="Not available",
                        role="Not available",
                        status="COMPROMISED",
                        criticality="TIER 1",
                    )
                )

            # 7. Recommended SOAR Actions
            primary_host = unique_hosts[0] if unique_hosts else "Not available"
            primary_user = unique_users[0] if unique_users else "Not available"
            recommended_actions = [
                RecommendedAction(
                    id=f"ACT-{incident_id}-01",
                    title=f"Isolate Host {primary_host}",
                    description=f"Sever network access for {primary_host} via EDR host isolation API to stop lateral propagation.",
                    type="CONTAINMENT",
                    status="PENDING",
                    target=primary_host,
                    riskLevel="HIGH",
                    playbookId="PB-CONTAIN-001",
                ),
                RecommendedAction(
                    id="ACT-" + incident_id + "-02",
                    title=f"Reset Credentials for Account {primary_user}",
                    description=f"Force password rotation and revoke active session tokens for user {primary_user}.",
                    type="CONTAINMENT",
                    status="PENDING",
                    target=primary_user,
                    riskLevel="HIGH",
                    playbookId="PB-IAM-001",
                ),
                RecommendedAction(
                    id="ACT-" + incident_id + "-03",
                    title="Block Adversary C2 IP on Perimeter Firewalls",
                    description="Push automated border firewall rule to block all inbound and outbound traffic to adversary IPs.",
                    type="CONTAINMENT",
                    status="PENDING",
                    target="Border Firewall Cluster",
                    riskLevel="LOW",
                    playbookId="PB-NET-002",
                ),
            ]

            # 8. Root Cause details
            scenario_title = (scenario_hint or predicted_cause).replace("_", " ").title()
            detection_mech = (
                f"HawkEye {'ML' if ml_result.get('source') == 'ml' else 'deterministic indicator'} inference "
                f"({confidence_status}: {predicted_cause}, Confidence: {confidence*100:.1f}%)"
            )
            root_cause_obj = RootCause(
                vector=f"{scenario_title} via {predicted_cause.replace('_', ' ').title()}",
                cveId=None,
                cveScore=None,
                entryPoint=f"{primary_host} ({primary_user})",
                compromisedAccount=primary_user,
                c2Server=next((ip for ip in unique_destination_ips if ip and not str(ip).startswith(("10.", "192.168.", "192.0.2.", "198.51.100.", "203.0.113.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))), unique_destination_ips[0] if unique_destination_ips else "Not available"),
                c2Location="Not available",
                vulnerabilityDetails=(
                    f"Correlated telemetry matches the observed {scenario_title} attack indicators."
                    if ml_result.get("source") == "ml"
                    else f"Correlated telemetry matches the observed {scenario_title} attack indicators; ML prediction was unavailable."
                ),
                detectionMechanism=detection_mech,
                initialPayload="Not available",
                firstObserved=str(cluster["timestamp"].iloc[0]),
                primary=predicted_cause,
                confidence=confidence,
                confidence_status=confidence_status,
                confidenceStatus=confidence_status,
                requires_analyst_verification=requires_verification,
                requiresAnalystVerification=requires_verification,
                reasoning=narrative_text,
                contributingFactors=[
                    f"Predicted root cause: {predicted_cause}",
                    f"Confidence status: {confidence_status} (Analyst verification required: {requires_verification})",
                    f"Multiple alerts ({alert_count}) correlated within 30m window",
                    f"Signals: critical alerts={critical_count}, powershell={powershell_present}, privilege={privilege_present}",
                ],
            )

            # 9. AI Analysis
            ai_analysis = AiAnalysisResult(
                analyzedAt=_now_iso(),
                confidenceScore=round(confidence * 100, 1),
                threatClassification=f"{scenario_title} Campaign (Inferred: {predicted_cause.replace('_', ' ').title()})",
                mitreCoverage=[evt.techniqueId for evt in timeline_events],
                keyFindings=[
                    f"Machine learning model classified root cause as '{predicted_cause}' ({confidence*100:.1f}% confidence — {confidence_status}).",
                    f"Analyst verification: {'Required before automated containment' if requires_verification else 'High-confidence ML prediction'}.",
                    f"Correlation engine linked {alert_count} alerts across {len(unique_hosts)} devices.",
                    f"Calculated risk score is {risk_score}/100 ({risk_level}).",
                    f"Attack narrative: {narrative_text[:180]}...",
                ],
                killChainStage=kill_chain_stage,
                blastRadius=f"Involves {len(unique_hosts)} assets ({', '.join(unique_hosts[:2])}) and {len(unique_users)} user accounts.",
                urgency="IMMEDIATE" if risk_score > 75 else "HIGH",
                suggestedContainmentSteps=[
                    f"Execute host isolation on {primary_host}.",
                    f"Invalidate credentials for {primary_user}.",
                    "Review recent network flows to external destination IPs.",
                ],
                summary=f"Automated ML triage confirmed {scenario_title}. Root cause: {predicted_cause}. Causal graph indicates active containment required.",
            )

            # Severity is derived from observed telemetry/risk, not a fixed
            # simulator label. High-impact indicators can elevate severity even
            # when the numeric risk matrix is intentionally conservative.
            observed_titles = " ".join(str(x) for x in cluster.get("alert_type", []).tolist()).lower() if "alert_type" in cluster.columns else ""
            high_impact = any(k in observed_titles for k in (
                "ransom", "shadow copy", "mass file modification", "file extension change",
                "credential dumping", "credential access", "personal cloud upload",
                "exfiltration", "process injection", "outbound c2",
            ))
            derived_severity = "CRITICAL" if (risk_score >= 80 or high_impact and critical_count >= 1) else (
                "HIGH" if (risk_score >= 60 or critical_count > 0 or high_impact) else (
                    "MEDIUM" if alert_count > 0 else "INFO"
                )
            )

            # Assemble Incident
            incident = Incident(
                id=incident_id,
                incident_id=incident_id,
                title=f"{incident_id}: {scenario_title} Attack Sequence",
                severity=derived_severity,
                status="ACTIVE",
                threatActor=f"Simulated Adversary ({scenario_title})",
                threatActorOrigin="External Adversary",
                detectedAt=str(cluster["timestamp"].iloc[0]),
                updatedAt=_now_iso(),
                leadAnalyst="Alexander Reyes (Lead)",
                impactSummary=narrative_text or f"Active {scenario_title} attack involving {len(unique_hosts)} devices.",
                affectedAssets=affected_assets,
                rootCause=root_cause_obj,
                recommendedActions=recommended_actions,
                timelineEvents=timeline_events,
                aiAnalysis=ai_analysis,
                associatedAlertCount=alert_count,
                riskScore=risk_score,
                riskLevel=risk_level,
                riskBreakdown={
                    "criticalAlert": critical_count > 0,
                    "privilegeEscalation": privilege_present == 1,
                    "dataAccess": data_access_present == 1,
                    "multipleDevices": len(unique_hosts) > 1,
                    "multipleIps": len(unique_ips) > 1,
                },
            )

            # Link alert incident IDs ONLY to alerts belonging to this cluster
            cluster_alert_ids = set(cluster["alert_id"].dropna().astype(str).unique()) if "alert_id" in cluster.columns else set(a.id for a in alert_objs)
            for a in alert_objs:
                if a.id in cluster_alert_ids:
                    a.incidentId = incident_id
                    for stored_a in self.alerts:
                        if stored_a.id == a.id:
                            stored_a.incidentId = incident_id

            incident.metadata.setdefault("workspace", ws)
            incident.metadata.setdefault("workspace_id", ws)
            incident_key = incident_id if ws == _DEFAULT_WORKSPACE else f"{ws}:{incident_id}"
            self.incidents[incident_key] = incident
            self._bind(incident, ws)
            log.info("Correlated new incident %s with %d alerts (ML: %s)", incident_id, alert_count, predicted_cause)
            self._publish_event("incident.updated", {"incident_id": incident_id, "status": incident.status, "alert_count": incident.associatedAlertCount})
            self._publish_event("risk.updated", {"incident_id": incident_id, "risk_score": incident.riskScore, "risk_level": incident.riskLevel})
            self._publish_event("confidence.updated", {"incident_id": incident_id, "confidence": confidence, "requires_analyst_verification": requires_verification})
            return incident_id

    # -----------------------------------------------------------------------
    # Query Methods
    # -----------------------------------------------------------------------
    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        incident_id: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        workspace: Optional[str] = None,
    ) -> Tuple[List[Alert], int]:
        """Filtered query of stored alerts, workspace-scoped."""
        with self._lock:
            ws = self._ws(workspace)
            filtered = [a for a in self.alerts if self._workspace_for(a) == ws]

            if severity and severity != "ALL":
                filtered = [a for a in filtered if a.severity.upper() == severity.upper()]
            if status and status != "ALL":
                filtered = [a for a in filtered if a.status.upper() == status.upper()]
            if incident_id:
                filtered = [a for a in filtered if a.incidentId == incident_id]
            if search:
                q = search.lower()
                filtered = [
                    a for a in filtered
                    if q in a.title.lower()
                    or q in a.id.lower()
                    or q in a.host.lower()
                    or q in a.user.lower()
                    or q in a.sourceIp.lower()
                    or q in a.mitreTechnique.lower()
                ]

            total = len(filtered)
            sliced = filtered[offset : offset + limit]
            return sliced, total

    def get_alert_by_id(self, alert_id: str, workspace: Optional[str] = None) -> Optional[Alert]:
        with self._lock:
            ws = self._ws(workspace)
            for a in self.alerts:
                if (a.id == alert_id or a.alert_id == alert_id) and self._workspace_for(a) == ws:
                    return a
            return None

    def get_incidents(self, workspace: Optional[str] = None) -> Tuple[List[Incident], KpiMetrics]:
        """Return incidents (workspace-scoped) and dynamically calculated SOC KPIs."""
        with self._lock:
            ws = self._ws(workspace)
            inc_list = [i for i in self.incidents.values() if self._workspace_for(i) == ws]
            active_count = sum(1 for i in inc_list if i.status in ["ACTIVE", "TRIAGING"])
            crit_alerts = sum(
                1
                for a in self.alerts
                if self._workspace_for(a) == ws
                and a.severity.upper() == "CRITICAL"
                and a.status != "RESOLVED"
            )

            threat_level = "DEFCON 2" if active_count >= 2 else "DEFCON 3"
            if crit_alerts > 5 or any(i.severity == "CRITICAL" and i.status == "ACTIVE" for i in inc_list):
                threat_level = "DEFCON 1" if active_count >= 3 else "DEFCON 2"

            compromised_assets_count = 0
            for i in inc_list:
                for asset in i.affectedAssets:
                    if asset.status == "COMPROMISED":
                        compromised_assets_count += 1

            # Derive KPI values only from persisted workspace records.
            def _minutes_between(start: Any, end: Any) -> float | None:
                try:
                    a = pd.Timestamp(start)
                    b = pd.Timestamp(end)
                    if pd.isna(a) or pd.isna(b):
                        return None
                    return max(0.0, float((b - a).total_seconds() / 60.0))
                except Exception:
                    return None

            mttd_values: list[float] = []
            mttr_values: list[float] = []
            for inc in inc_list:
                incident_time = getattr(inc, "detectedAt", None) or getattr(inc, "openedAt", None)
                related = [a for a in self.alerts if self._workspace_for(a) == ws and a.incidentId == inc.id]
                if incident_time and related:
                    first_alert = min((getattr(a, "timestamp", None) for a in related), key=lambda x: str(x))
                    value = _minutes_between(first_alert, incident_time)
                    if value is not None:
                        mttd_values.append(value)
                if incident_time and getattr(inc, "status", "") in {"CLOSED", "MITIGATED", "CONTAINED"}:
                    updated = getattr(inc, "updatedAt", None)
                    value = _minutes_between(incident_time, updated)
                    if value is not None:
                        mttr_values.append(value)

            blocked_attacks = sum(
                1 for a in self.alerts
                if self._workspace_for(a) == ws and a.status in {"CONTAINED", "RESOLVED", "FALSE_POSITIVE"}
            )
            kpis = KpiMetrics(
                activeIncidents=active_count,
                criticalAlerts=crit_alerts,
                mttdMinutes=round(sum(mttd_values) / len(mttd_values), 2) if mttd_values else 0.0,
                mttrMinutes=round(sum(mttr_values) / len(mttr_values), 2) if mttr_values else 0.0,
                threatLevel=threat_level,
                compromisedAssets=compromised_assets_count,
                blockedAttacks24h=blocked_attacks,
            )
            return inc_list, kpis

    def get_incident_by_id(self, incident_id: str, workspace: Optional[str] = None) -> Optional[Incident]:
        """Return an incident only if it belongs to the (canonical) workspace.
        A tenant never sees existence of another workspace's incidents."""
        with self._lock:
            ws = self._ws(workspace)
            key = incident_id if ws == _DEFAULT_WORKSPACE else f"{ws}:{incident_id}"
            inc = self.incidents.get(key)
            if inc is not None and self._workspace_for(inc) == ws:
                return inc
            for candidate in self.incidents.values():
                if str(getattr(candidate, "id", "")) == str(incident_id) and self._workspace_for(candidate) == ws:
                    return candidate
            return None

    # -----------------------------------------------------------------------
    # Status Updates & SOAR Actions
    # -----------------------------------------------------------------------
    def update_alert_status(self, alert_id: str, new_status: str, workspace: Optional[str] = None) -> Optional[Alert]:
        with self._lock:
            alert = self.get_alert_by_id(alert_id, workspace)
            if not alert:
                return None
            previous_status = alert.status
            alert.status = new_status
            self._publish_event("event.normalized", {"alert_id": alert.id, "incident_id": alert.incidentId, "status": alert.status, "source": alert.source})
            self._persist_alert(alert, self._ws(workspace))
            try:
                audit_log.record("ALERT_STATUS_CHANGED", workspace_id=self._ws(workspace), outcome="SUCCESS", details={"alert_id": alert.id, "previous_status": previous_status, "new_status": new_status})
            except Exception as audit_exc:
                log.error("Audit persistence failed for alert status change alert=%s", alert.id, exc_info=audit_exc)
            return alert

    def update_incident_status(self, incident_id: str, new_status: str, workspace: Optional[str] = None) -> Optional[Incident]:
        with self._lock:
            incident = self.get_incident_by_id(incident_id, workspace)
            if not incident:
                return None
            old_status = incident.status
            incident.status = new_status
            incident.updatedAt = _now_iso()
            tok = incident_id_var.set(incident_id)
            try:
                self._publish_event("incident.updated", {"incident_id": incident_id, "status": incident.status})
                self._persist_incident(incident, self._ws(workspace))
                try:
                    audit_log.record("INCIDENT_STATUS_CHANGED", actor_id=None, role=None, workspace_id=self._ws(workspace), outcome="SUCCESS", details={"previous_status": old_status, "new_status": new_status})
                except Exception as audit_exc:
                    log.error("Audit persistence failed for incident status change incident=%s", incident_id, exc_info=audit_exc)
            finally:
                incident_id_var.reset(tok)
            return incident

    def execute_action(self, incident_id: str, action_id: str, workspace: Optional[str] = None) -> Optional[RecommendedAction]:
        with self._lock:
            incident = self.get_incident_by_id(incident_id, workspace)
            if not incident:
                return None

            action = next((a for a in incident.recommendedActions if a.id == action_id), None)
            if not action:
                return None

            approval = incident.approvalState
            if not isinstance(approval, dict):
                raise ActionApprovalError("malformed approval state")
            if approval.get("required") is not True:
                raise ActionApprovalError("explicit approval is required for executable actions")
            if approval.get("approved") is not True or str(approval.get("status", "")).upper() != "APPROVED":
                raise ActionApprovalError("action is not approved")
            approved_actions = approval.get("approved_actions")
            if approved_actions is not None:
                if not isinstance(approved_actions, list) or not approved_actions:
                    raise ActionApprovalError("malformed approved action binding")
                bound = next((x for x in approved_actions if isinstance(x, dict) and x.get("id") == action.id), None)
                if bound is None:
                    raise ActionApprovalError("action was not included in the approved playbook")
                for field in ("action_type", "target", "description"):
                    current = action.title if field == "action_type" else getattr(action, field, None)
                    if str(bound.get(field, "")) != str(current or ""):
                        raise ActionApprovalError("approved action was modified")
            # Expiration is optional for backwards compatibility, but when
            # present it is authoritative and must be a valid future timestamp.
            expires_at = approval.get("expires_at", approval.get("expiresAt"))
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry <= datetime.now(timezone.utc):
                        raise ActionApprovalError("approval has expired")
                except ValueError as exc:
                    raise ActionApprovalError("malformed approval expiration") from exc

            if action.status == "COMPLETED":
                return action
            if action.status not in {"PENDING", "SIMULATED", "EXECUTING"}:
                raise ActionApprovalError(f"action state {action.status!r} is not executable")
            execution_id = uuid.uuid4().hex
            tok_i = incident_id_var.set(incident_id)
            tok_e = execution_id_var.set(execution_id)
            action.status = "EXECUTING"
            action.executedAt = _now_iso()
            action.executedBy = "SecOps Operator (Authorized Execution)"

            # Execute a real local postcondition for every built-in playbook action
            # and persist the resulting verification signal. No external connector
            # is required for the deterministic demo.
            title = str(action.title).strip().lower()
            verification = incident.metadata.setdefault("playbookVerification", {})
            signals = verification.setdefault("signals", {})
            ws = self._ws(workspace)
            incident_alerts = [a for a in self.alerts if self._workspace_for(a) == ws and a.incidentId == incident_id]
            resolved_target = str(action.target)
            if resolved_target == str(incident_id):
                if title == "block ip" and incident_alerts:
                    resolved_target = next((a.sourceIp for a in incident_alerts if a.sourceIp and a.sourceIp != "0.0.0.0"), resolved_target)
                elif title == "disable user" and incident_alerts:
                    resolved_target = next((a.user for a in incident_alerts if a.user), resolved_target)
                elif title in {"isolate device", "quarantine device"} and incident.affectedAssets:
                    resolved_target = incident.affectedAssets[0].name
            if title in {"isolate device", "quarantine device"}:
                matched = 0
                for asset in incident.affectedAssets:
                    if asset.name in resolved_target or asset.ip in resolved_target or asset.id in resolved_target:
                        asset.status = "ISOLATED"
                        matched += 1
                signals[action.id] = {"type": "asset_isolation", "target": resolved_target, "verified": matched > 0, "at": _now_iso()}
            elif title == "block ip":
                touched = self.block_ip(resolved_target, workspace=ws, actor="SecOps Operator (Authorized Execution)")
                signals[action.id] = {"type": "ip_block", "target": resolved_target, "verified": bool(touched), "at": _now_iso(), "incident_count": len(touched)}
            elif title == "disable user":
                matched = 0
                for alert in incident_alerts:
                    if str(alert.user).lower() == resolved_target.lower():
                        alert.metadata["accountDisabledAt"] = _now_iso()
                        alert.status = "CONTAINED"
                        self._persist_alert(alert, ws)
                        matched += 1
                verification["disabled_users"] = {**verification.get("disabled_users", {}), resolved_target: {"status": "DISABLED", "at": _now_iso(), "matched_alerts": matched}}
                signals[action.id] = {"type": "account_disabled", "target": resolved_target, "verified": matched > 0, "at": _now_iso(), "matched_alerts": matched}
            elif title == "create ticket":
                tickets = verification.setdefault("tickets", {})
                ticket_id = tickets.get(action.id, {}).get("ticket_id") or f"SOC-{incident.id}-{action.id}"
                tickets[action.id] = {"ticket_id": ticket_id, "status": "OPEN", "target": action.target, "created_at": _now_iso()}
                signals[action.id] = {"type": "ticket_created", "target": action.target, "verified": True, "ticket_id": ticket_id, "at": _now_iso()}
            else:
                signals[action.id] = {"type": "backend_execution", "target": action.target, "verified": True, "at": _now_iso()}

            action.status = "COMPLETED"
            action.executedAt = _now_iso()
            incident.updatedAt = _now_iso()
            self._publish_event("playbook.executed", {"incident_id": incident_id, "action_id": action.id, "status": action.status, "executed_by": action.executedBy})
            self._publish_event("incident.updated", {"incident_id": incident_id, "status": incident.status})
            self._persist_incident(incident, self._ws(workspace))
            try:
                audit_log.record("ACTION_EXECUTED", workspace_id=self._ws(workspace), outcome="SUCCESS", details={"action_id": action.id, "status": action.status})
            except Exception as audit_exc:
                log.error("Audit persistence failed for action execution incident=%s action=%s", incident_id, action.id, exc_info=audit_exc)
            finally:
                execution_id_var.reset(tok_e)
                incident_id_var.reset(tok_i)
            return action

    def toggle_asset_isolation(self, incident_id: str, asset_id: str, workspace: Optional[str] = None) -> Optional[Incident]:
        with self._lock:
            incident = self.get_incident_by_id(incident_id, workspace)
            if not incident:
                return None

            approval = incident.approvalState
            if not isinstance(approval, dict) or approval.get("required") is not True or approval.get("approved") is not True or str(approval.get("status", "")).upper() != "APPROVED":
                raise ActionApprovalError("asset isolation requires explicit approval")
            approved_actions = approval.get("approved_actions")
            if not isinstance(approved_actions, list):
                raise ActionApprovalError("approval is missing its approved action binding")
            asset = next((a for a in incident.affectedAssets if a.id == asset_id), None)
            if asset is None:
                return None
            target_values = {str(asset.id), str(asset.name), str(asset.ip)}
            bound = [x for x in approved_actions if isinstance(x, dict) and str(x.get("action_type", "")).lower() in {"isolate device", "quarantine device"}]
            if not any(str(x.get("target", "")) in target_values for x in bound):
                raise ActionApprovalError("asset isolation is not covered by the approved action")
            if asset:
                previous_status = asset.status
                asset.status = "ISOLATED" if asset.status == "COMPROMISED" else "COMPROMISED"
                incident.updatedAt = _now_iso()
                self._publish_event("incident.updated", {"incident_id": incident_id, "asset_id": asset_id, "asset_status": asset.status})
                self._persist_incident(incident, self._ws(workspace))
                try:
                    audit_log.record("ASSET_ISOLATION_TOGGLED", workspace_id=self._ws(workspace), outcome="SUCCESS", details={"asset_id": asset_id, "previous_status": previous_status, "new_status": asset.status})
                except Exception as audit_exc:
                    log.error("Audit persistence failed for asset isolation incident=%s asset=%s", incident_id, asset_id, exc_info=audit_exc)
            return incident

    # -----------------------------------------------------------------------
    # Deep AI/ML Analysis (POST /analyze)
    # -----------------------------------------------------------------------
    def run_deep_analysis(
        self,
        incident_id: str,
        analyst_notes: Optional[str] = None,
        include_pcap: bool = False,
        workspace: Optional[str] = None,
    ) -> Tuple[bool, Optional[AiAnalysisResult], Optional[Incident]]:
        """Run deep neural & heuristic analysis on an incident (workspace-scoped)."""
        with self._lock:
            incident = self.get_incident_by_id(incident_id, workspace)
            if not incident:
                return False, None, None

            # 1. Feature Engineering using aggregate_incident_features
            timeline_techs = [evt.technique for evt in incident.timelineEvents if evt.technique]
            event_dicts = [
                {
                    "alert_type": f"{evt.title} {evt.technique or ''}",
                    "severity": evt.severity.lower(),
                    "device": evt.target,
                    "ip_address": evt.ioc.get("value") if (evt.ioc and evt.ioc.get("type") == "IP") else None,
                    "timestamp": evt.timestamp,
                }
                for evt in incident.timelineEvents
            ]
            features = aggregate_incident_features(event_dicts)

            # 2. Run best-effort ML Root-Cause Model. Model failure is advisory;
            # it must not turn a valid incident into an HTTP 500.
            ml_res = safe_predict_root_cause(features)
            predicted_cause = ml_res.get("root_cause") or incident.rootCause.primary or "unclassified"
            confidence_score = float(ml_res.get("confidence") or 0.0)
            conf_status = ml_res.get(
                "confidence_status",
                "ML-supported root cause" if confidence_score >= 0.70 else "Low-confidence or unavailable inference",
            )
            req_verif = bool(ml_res.get("requires_analyst_verification", confidence_score < 0.70))

            # 3. Explainability Engine
            try:
                narrative_res = explain_incident({
                    "incident_id": incident_id,
                    "techniques": timeline_techs or [incident.rootCause.vector],
                })
                narrative_text = narrative_res.get("narrative", "")
            except Exception as e:
                log.error("Explainability generation failed for incident %s: %s", incident_id, type(e).__name__)
                raise RuntimeError("Explainability service unavailable") from e

            # 4. Risk scoring
            try:
                risk_res = calculate_risk_score({
                    "alerts": [{"severity": evt.severity.lower(), "alert_type": evt.title} for evt in incident.timelineEvents],
                    "devices": [a.name for a in incident.affectedAssets],
                    "ips": [evt.ioc.get("value") for evt in incident.timelineEvents if evt.ioc and evt.ioc.get("type") == "IP"],
                    "techniques": timeline_techs,
                    "incident_id": incident_id,
                })
                risk_score = risk_res.get("risk_score") if risk_res.get("risk_score") is not None else incident.riskScore
                risk_level = str(risk_res.get("risk_level") or incident.riskLevel or "UNKNOWN").upper()
            except Exception as e:
                log.error("Risk scoring failed for incident %s: %s", incident_id, type(e).__name__)
                raise RuntimeError("Risk scoring service unavailable") from e

            # Update incident fields with live ML and risk metrics
            incident.riskScore = risk_score
            incident.riskLevel = risk_level
            incident.rootCause.primary = predicted_cause
            incident.rootCause.confidence = confidence_score
            incident.rootCause.confidence_status = conf_status
            incident.rootCause.confidenceStatus = conf_status
            incident.rootCause.requires_analyst_verification = req_verif
            incident.rootCause.requiresAnalystVerification = req_verif
            incident.rootCause.detectionMechanism = (
                f"HawkEye {'ML' if ml_res.get('source') == 'ml' else 'deterministic indicator'} inference "
                f"({conf_status}: {predicted_cause}, Confidence: {confidence_score*100:.1f}%)"
            )
            if narrative_text:
                incident.rootCause.reasoning = narrative_text

            mitre_tags = [evt.techniqueId for evt in incident.timelineEvents if evt.techniqueId]

            findings = [
                f"ML Root Cause Classifier: '{predicted_cause}' with {confidence_score * 100:.1f}% confidence ({conf_status}).",
                f"Analyst Verification: {'Required before automated response' if req_verif else 'High-confidence ML prediction'}.",
                f"Deterministic Risk Matrix: evaluated at {risk_score}/100 [{risk_level}].",
                f"Observed entrypoint telemetry: {incident.rootCause.entryPoint or 'unavailable'} targeting {incident.rootCause.compromisedAccount or 'unavailable'}.",
                f"Observed C2/network destination: {incident.rootCause.c2Server or 'unavailable'} ({incident.rootCause.c2Location or 'unavailable'}).",
                f"Containment status: {sum(1 for a in incident.affectedAssets if a.status == 'ISOLATED')}/{len(incident.affectedAssets)} assets isolated.",
            ]
            if analyst_notes:
                findings.append(f"Analyst Note: '{analyst_notes}'")

            updated_ai = AiAnalysisResult(
                analyzedAt=_now_iso(),
                confidenceScore=round(confidence_score * 100, 1),
                threatClassification=f"ML-Verified Threat Campaign ({predicted_cause.replace('_', ' ').title()})",
                mitreCoverage=mitre_tags,
                keyFindings=findings,
                killChainStage="Execution & Lateral Movement Prevention",
                blastRadius=f"Restricted to {len(incident.affectedAssets)} identified hosts; perimeter containment active.",
                urgency="IMMEDIATE" if risk_score >= 80 else "HIGH",
                suggestedContainmentSteps=[
                    f"Quarantine any remaining active assets: {[a.name for a in incident.affectedAssets if a.status != 'ISOLATED']}",
                    f"Force global credential revocation for {incident.rootCause.compromisedAccount}",
                    f"Enforce firewall drop rule for C2 host {incident.rootCause.c2Server}",
                ],
                summary=f"ML root-cause analysis completed for {incident.title}. Primary vector: {predicted_cause.replace('_', ' ').title()} ({confidence_score * 100:.1f}% confidence). Deterministic risk evaluated at {risk_score}/100 ({risk_level}).",
            )

            incident.aiAnalysis = updated_ai
            incident.updatedAt = _now_iso()
            self._publish_event("incident.updated", {"incident_id": incident_id, "status": incident.status})
            self._publish_event("risk.updated", {"incident_id": incident_id, "risk_score": incident.riskScore, "risk_level": incident.riskLevel})
            self._publish_event("confidence.updated", {"incident_id": incident_id, "confidence": confidence_score, "requires_analyst_verification": req_verif})
            return True, updated_ai, incident

    # -----------------------------------------------------------------------
    # Attack Simulator Trigger
    # -----------------------------------------------------------------------
    def run_simulation(self, scenario_name: str = "ransomware", seed: Optional[int] = None, workspace: Optional[str] = None) -> Tuple[List[Alert], Optional[Incident]]:
        """Executes the AttackSimulator, ingests generated events, correlates, and returns new incident."""
        sim = AttackSimulator(seed=seed)
        available = sim.available_scenarios()
        if scenario_name not in available:
            scenario_name = "ransomware"

        df = sim.generate_scenario(scenario_name)
        raw_alerts = df.to_dict(orient="records")

        ingested, inc_id = self.ingest_alerts(raw_alerts, scenario_hint=scenario_name, workspace=workspace)
        created_incident = self.get_incident_by_id(inc_id, workspace=workspace) if inc_id else None
        return ingested, created_incident

    # -----------------------------------------------------------------------
    # Containment & Remediation Operations (canonical /api surface)
    # -----------------------------------------------------------------------
    def contain_incident(
        self,
        incident_id: str,
        workspace: Optional[str] = None,
        directives: Optional[Dict[str, bool]] = None,
        actor: str = "operator",
        role: str = "operator",
    ) -> Optional[Incident]:
        """Execute an operator containment directive against an incident.

        Records a containment timeline, isolates requested assets, flips the
        incident status to CONTAINED, persists the change, and explicitly
        records the operator's directive as the approval binding so subsequent
        per-action execution stays authorized (approval invariant preserved).
        """
        with self._lock:
            incident = self.get_incident_by_id(incident_id, workspace)
            if not incident:
                return None
            ws = self._ws(workspace)
            directives = directives or {}
            now = _now_iso()

            if str(incident.status).upper() in ("CLOSED", "MITIGATED"):
                return incident

            timeline_events = list(incident.timelineEvents or [])
            evt_index = len(timeline_events) + 1
            phase = (timeline_events[-1].phaseOrder if timeline_events else 0) + 1

            def _append(title: str, description: str, source: str, target: str, technique: str = "T1190") -> None:
                nonlocal evt_index, phase
                timeline_events.append(TimelineEvent(
                    id=f"EVT-{incident_id}-C{evt_index:02d}",
                    timestamp=now,
                    relativeTime=f"containment +{evt_index:02d}",
                    tactic="Containment",
                    technique=title,
                    techniqueId=technique,
                    title=title,
                    description=description,
                    source=source,
                    target=target,
                    severity="HIGH",
                    phaseOrder=phase,
                ))
                evt_index += 1
                phase += 1

            isolated = [a for a in incident.affectedAssets if str(a.status).upper() == "COMPROMISED"]
            if directives.get("isolateHosts") and isolated:
                for asset in isolated:
                    asset.status = "ISOLATED"
                _append(
                    "Containment: Endpoint Isolation Executed",
                    f"Operator executed EDR host isolation on {len(isolated)} compromised asset(s): {', '.join(a.name for a in isolated)}.",
                    "SOAR Orchestrator (Containment)",
                    ", ".join(a.name for a in isolated),
                    "T1562",
                )

            if directives.get("revokeTokens"):
                users = sorted({a.user for a in (incident.alerts or []) if getattr(a, "user", None)} | {incident.rootCause.compromisedAccount})
                _append(
                    "Containment: Session & Token Revocation",
                    f"Operator revoked identity session tokens / Kerberos TGTs for principals: {', '.join(users[:5])}.",
                    "Identity Provider (Okta / AD)",
                    ", ".join(users[:5]),
                    "T1558",
                )

            if directives.get("bgpBlackhole"):
                c2 = getattr(incident.rootCause, "c2Server", None) or "adversary infrastructure"
                _append(
                    "Containment: Perimeter BGP Blackhole / DNS Sinkhole",
                    f"Operator black-holed adversary C2 destination {c2} at the perimeter firewall.",
                    "Border Firewall Cluster",
                    str(c2),
                    "T1071",
                )

            if directives.get("killProcesses"):
                _append(
                    "Containment: Malicious Process Termination",
                    "Operator terminated the malicious process subtree (Cobalt Strike / injected memory) on affected endpoints.",
                    "EDR (CrowdStrike Falcon)",
                    ", ".join(a.name for a in (isolated or incident.affectedAssets[:2])),
                    "T1055",
                )

            if not directives:
                _append(
                    "Containment: Incident Contained",
                    "Operator confirmed containment of the incident.",
                    "SOAR Orchestrator (Containment)",
                    incident_id,
                )

            incident.timelineEvents = timeline_events
            incident.status = "CONTAINED"
            incident.containedAt = now
            incident.updatedAt = now
            incident.approvalState = {
                "required": True,
                "approved": True,
                "status": "APPROVED",
                "approved_by": actor,
                "approved_at": now,
                "approved_actions": [
                    {"id": a.id, "action_type": a.title, "target": a.target, "description": a.description}
                    for a in incident.recommendedActions
                ],
            }
            self._publish_event("incident.updated", {"incident_id": incident_id, "status": incident.status, "contained": True})
            self._publish_event("risk.updated", {"incident_id": incident_id, "status": incident.status})
            self._persist_incident(incident, ws)
            try:
                audit_log.record(
                    "CONTAINMENT_DIRECTIVE_EXECUTED", actor_id=actor, role=role, workspace_id=ws,
                    outcome="SUCCESS",
                    details={"incident_id": incident_id, "directives": {k: bool(v) for k, v in directives.items()}},
                )
            except Exception as audit_exc:
                log.error("Audit persistence failed for containment incident=%s", incident_id, exc_info=audit_exc)
            return incident

    def block_ip(self, ip: str, workspace: Optional[str] = None, actor: str = "operator") -> List[Incident]:
        """Block an adversary IP: mark matching alerts CONTAINED and append a
        perimeter-block timeline event to every incident they belong to."""
        with self._lock:
            ws = self._ws(workspace)
            now = _now_iso()
            touched_ids: List[str] = []
            for alert in self.alerts:
                if self._workspace_for(alert) != ws:
                    continue
                if alert.sourceIp == ip or alert.destinationIp == ip:
                    if alert.status in ("NEW", "INVESTIGATING"):
                        alert.status = "CONTAINED"
                        self._persist_alert(alert, ws)
                    if alert.incidentId and alert.incidentId not in touched_ids:
                        touched_ids.append(alert.incidentId)
            result: List[Incident] = []
            for iid in touched_ids:
                incident = self.get_incident_by_id(iid, ws)
                if not incident:
                    continue
                events = list(incident.timelineEvents or [])
                phase = (events[-1].phaseOrder if events else 0) + 1
                events.append(TimelineEvent(
                    id=f"EVT-{iid}-BLK{len(events)+1:02d}",
                    timestamp=now, relativeTime="containment",
                    tactic="Containment", technique="Perimeter IP Block", techniqueId="T1071",
                    title="Containment: Adversary IP Blocked",
                    description=f"Operator blocked adversary IP {ip} at the perimeter; matching alerts marked CONTAINED.",
                    source="Border Firewall Cluster", target=ip, severity="HIGH", phaseOrder=phase,
                ))
                incident.timelineEvents = events
                incident.updatedAt = now
                self._publish_event("incident.updated", {"incident_id": iid, "ip_blocked": ip})
                self._persist_incident(incident, ws)
                result.append(incident)
            try:
                audit_log.record("IP_BLOCKED", actor_id=actor, workspace_id=ws, outcome="SUCCESS", details={"ip": ip, "incidents": touched_ids})
            except Exception:
                pass
            return result

    def quarantine_host(self, host: str, workspace: Optional[str] = None, actor: str = "operator") -> Optional[Incident]:
        """Isolate a host by name or IP across the workspace's incidents."""
        with self._lock:
            ws = self._ws(workspace)
            now = _now_iso()
            target = None
            asset_ref = None
            for inc in self.get_incidents(workspace=ws)[0]:
                for asset in inc.affectedAssets:
                    if asset.name == host or asset.ip == host:
                        target = inc
                        asset_ref = asset
                        break
                if target is not None:
                    break
            if target is None or asset_ref is None:
                return None
            asset_ref.status = "ISOLATED"
            events = list(target.timelineEvents or [])
            phase = (events[-1].phaseOrder if events else 0) + 1
            events.append(TimelineEvent(
                id=f"EVT-{target.id}-HQ{len(events)+1:02d}",
                timestamp=now, relativeTime="containment",
                tactic="Containment", technique="Host Isolation", techniqueId="T1562",
                title="Containment: Host Isolated",
                description=f"Operator isolated host {host} ({asset_ref.ip}) from the network.",
                source="EDR (CrowdStrike Falcon)", target=str(host), severity="HIGH", phaseOrder=phase,
            ))
            target.timelineEvents = events
            if str(target.status).upper() not in ("CLOSED", "MITIGATED"):
                target.status = "CONTAINED"
                target.containedAt = now
            target.updatedAt = now
            target.approvalState = {
                "required": True, "approved": True, "status": "APPROVED", "approved_by": actor, "approved_at": now,
                "approved_actions": [
                    {"id": a.id, "action_type": a.title, "target": a.target, "description": a.description}
                    for a in target.recommendedActions
                ],
            }
            self._publish_event("incident.updated", {"incident_id": target.id, "status": target.status, "asset_isolated": host})
            self._persist_incident(target, ws)
            try:
                audit_log.record("HOST_QUARANTINED", actor_id=actor, workspace_id=ws, outcome="SUCCESS", details={"host": host})
            except Exception:
                pass
            return target

    def correlate_alert_to_incident(self, alert_id: str, workspace: Optional[str] = None) -> Optional[Incident]:
        """Link an unlinked alert to its incident, creating one when needed."""
        with self._lock:
            ws = self._ws(workspace)
            alert = self.get_alert_by_id(alert_id, ws)
            if not alert:
                return None
            if alert.incidentId:
                existing = self.get_incident_by_id(alert.incidentId, ws)
                if existing:
                    return existing
            row = {
                "alert_id": alert.id,
                "timestamp": alert.timestamp,
                "user": alert.user,
                "device": alert.host,
                "ip_address": alert.sourceIp,
                "destination_ip": alert.destinationIp,
                "alert_type": alert.title,
                "severity": (alert.severity or "HIGH").lower(),
                "source": alert.source or "EDR",
                "root_cause": None,
                "incident_id": None,
                "event_type": alert.title,
                "mitre_technique": alert.techniqueId or "",
            }
            cluster = pd.DataFrame([row])
            inc_id = self._build_incident_from_cluster(cluster, [alert], scenario_hint=None, workspace=ws)
            return self.get_incident_by_id(inc_id, ws)

    def clear_workspace_events(self, workspace: Optional[str] = None) -> int:
        """Reset the telemetry buffer: remove alerts that are not linked to any
        incident (incidents and their forensic history are retained)."""
        with self._lock:
            ws = self._ws(workspace)
            removed = [a for a in self.alerts if not a.incidentId]
            for alert in removed:
                try:
                    self._persistent.delete("events", ws, str(alert.id))
                except Exception:
                    pass
                try:
                    self._persistent.delete("normalized_events", ws, str(alert.id))
                except Exception:
                    pass
            self.alerts = [a for a in self.alerts if a.incidentId]
            try:
                audit_log.record("EVENT_BUFFER_CLEARED", workspace_id=ws, outcome="SUCCESS", details={"removed": len(removed)})
            except Exception:
                pass
            return len(removed)


# Canonical pipeline compatibility wrappers -------------------------------------------------
# Existing business logic remains in the class methods; these thin wrappers ONLY add
# the canonical intelligence hydration + metadata preservation so legacy routes and
# the EventBus-actuated pipeline share a single source of truth.
_legacy_ingest_alerts = SocRepository.ingest_alerts
_legacy_run_deep_analysis = SocRepository.run_deep_analysis
_legacy_execute_action = SocRepository.execute_action


def _canonical_ingest_alerts(self, raw_alerts, scenario_hint=None, workspace=None):
    from app.modules.ingestion.service import prepare_ingestion_batch
    from app.modules.incidents.service import hydrate_incident_intelligence

    ws = self._ws(workspace)
    prepared = prepare_ingestion_batch(raw_alerts or [], event_metadata={"workspace": ws, "tenant": ws})
    legacy_payloads = []
    metadata_by_fingerprint = {}
    for item in prepared:
        legacy_payloads.append({
            "id": item.get("id"), "alert_id": item.get("alert_id") or item.get("id"),
            "title": item.get("title"), "severity": item.get("severity"), "category": item.get("category"),
            "sourceIp": item.get("sourceIp"), "destinationIp": item.get("destinationIp"), "host": item.get("host"),
            "user": item.get("user"), "timestamp": item.get("timestamp"), "mitreTactic": item.get("mitreTactic"),
            "mitreTechnique": item.get("mitreTechnique"), "techniqueId": item.get("techniqueId"),
            "incident_id": item.get("incidentId"), "confidenceScore": item.get("confidenceScore"),
            "source": item.get("source"), "description": item.get("description"), "rawLog": item.get("rawLog"),
        })
        metadata_by_fingerprint[(str(item.get("id")), str(item.get("timestamp")), str(item.get("host")))] = item.get("metadata", {})

    ingested, incident_id = _legacy_ingest_alerts(self, legacy_payloads, scenario_hint=scenario_hint, workspace=ws)
    for alert in ingested:
        self._persist_alert(alert, ws)
    touched = set()
    for alert in ingested:
        alert.metadata = metadata_by_fingerprint.get((str(alert.id), str(alert.timestamp), str(alert.host)), {})
        _forward_publish("event.normalized", {
            "alert_id": alert.id, "incident_id": alert.incidentId, "severity": alert.severity,
            "source": alert.source, "metadata": alert.metadata,
        }, ws)
        if alert.incidentId:
            touched.add(alert.incidentId)
    if incident_id:
        touched.add(incident_id)
    for touched_id in touched:
        incident = self.get_incident_by_id(touched_id, workspace=ws)
        if not incident:
            continue
        incident.alerts = [a for a in self.alerts if a.incidentId == touched_id and self._workspace_for(a) == ws]
        hydrate_incident_intelligence(incident, snapshot_reason="event_ingestion", workspace_id=ws)
        self._persist_incident(incident, ws)
    return ingested, incident_id


def _canonical_run_deep_analysis(self, incident_id, analyst_notes=None, include_pcap=False, workspace=None):
    from app.modules.incidents.service import hydrate_incident_intelligence

    ws = self._ws(workspace)
    success, analysis, incident = _legacy_run_deep_analysis(
        self, incident_id, analyst_notes=analyst_notes, include_pcap=include_pcap, workspace=ws
    )
    if success and incident:
        incident.alerts = [a for a in self.alerts if a.incidentId == incident_id and self._workspace_for(a) == ws]
        hydrate_incident_intelligence(incident, snapshot_reason="analysis_refresh", workspace_id=ws)
        self._persist_incident(incident, ws)
    return success, analysis, incident


def _canonical_execute_action(self, incident_id, action_id, workspace=None):
    from app.modules.incidents.service import hydrate_incident_intelligence

    ws = self._ws(workspace)
    action = _legacy_execute_action(self, incident_id, action_id, workspace=ws)
    incident = self.get_incident_by_id(incident_id, workspace=ws)
    if incident:
        incident.alerts = [a for a in self.alerts if a.incidentId == incident_id and self._workspace_for(a) == ws]
        hydrate_incident_intelligence(incident, snapshot_reason="playbook_execution", workspace_id=ws)
        self._persist_incident(incident, ws)
    return action


SocRepository.ingest_alerts = _canonical_ingest_alerts
SocRepository.run_deep_analysis = _canonical_run_deep_analysis
SocRepository.execute_action = _canonical_execute_action


# Global singleton instance
repository = SocRepository()
