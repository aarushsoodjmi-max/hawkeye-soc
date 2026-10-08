"""
HawkEye SOC — Canonical Pydantic Schemas
========================================
Unifies alert and incident schemas across all modules:
- Simulator
- Ingestion
- Correlation Engine
- ML Root Cause Predictor
- Analytics & Risk Scoring
- Reporting
- Frontend HawkEye Console
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums / Literal Types
# ---------------------------------------------------------------------------
SeverityType = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
AlertStatusType = Literal["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]
IncidentStatusType = Literal["ACTIVE", "TRIAGING", "CONTAINED", "MITIGATED", "CLOSED"]
ActionStatusType = Literal["PENDING", "EXECUTING", "COMPLETED", "FAILED"]


# ---------------------------------------------------------------------------
# Alert Model
# ---------------------------------------------------------------------------
class Alert(BaseModel):
    id: str = Field(..., description="Unique alert ID, e.g. ALT-1001")
    title: str = Field(..., description="Human-readable alert title")
    severity: str = Field("HIGH", description="Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    category: str = Field("General", description="Alert category or tactic")
    sourceIp: str = Field("0.0.0.0", description="Source IP address")
    destinationIp: str = Field("0.0.0.0", description="Destination IP address")
    host: str = Field("UNKNOWN-HOST", description="Hostname or device identifier")
    user: str = Field("system", description="Username associated with event")
    timestamp: str = Field(..., description="ISO 8601 timestamp string")
    mitreTactic: str = Field("Execution", description="MITRE ATT&CK tactic")
    mitreTechnique: str = Field("Unknown", description="MITRE ATT&CK technique name")
    techniqueId: str = Field("T1059", description="MITRE ATT&CK technique ID")
    status: str = Field("NEW", description="Alert lifecycle status")
    incidentId: Optional[str] = Field(None, description="Linked incident ID, e.g. INC-8942")
    confidenceScore: float = Field(85.0, description="Correlation confidence (0-100)")
    rawLog: Optional[str] = Field(None, description="Raw log telemetry snippet")
    # Backend compatibility aliases
    alert_id: Optional[str] = None
    source: Optional[str] = "EDR"
    description: Optional[str] = None
    root_cause: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Preserved event metadata including tenant/workspace context")

    model_config = ConfigDict(populate_by_name=True, extra="allow")


# ---------------------------------------------------------------------------
# Incident Sub-Models
# ---------------------------------------------------------------------------
class AffectedAsset(BaseModel):
    id: str = Field(..., description="Asset identifier, e.g. AST-01")
    name: str = Field(..., description="Asset name / hostname")
    ip: str = Field(..., description="Internal IP address")
    os: str = Field(..., description="Operating system")
    role: str = Field(..., description="Asset role in infrastructure")
    status: str = Field("COMPROMISED", description="COMPROMISED, ISOLATED, MONITORED, CLEAN")
    criticality: str = Field("TIER 1", description="TIER 0, TIER 1, TIER 2")


class RootCause(BaseModel):
    vector: str = Field(..., description="Primary attack vector / vulnerability")
    cveId: Optional[str] = Field(None, description="Associated CVE if applicable")
    cveScore: Optional[float] = Field(None, description="CVSS score")
    entryPoint: str = Field(..., description="Initial infiltration entrypoint")
    compromisedAccount: str = Field(..., description="Identified compromised user account")
    c2Server: str = Field(..., description="Attacker command and control endpoint")
    c2Location: str = Field(..., description="Geographic origin of C2")
    vulnerabilityDetails: str = Field(..., description="Technical breakdown of vulnerability")
    detectionMechanism: str = Field(..., description="Detection sensor and rule")
    initialPayload: str = Field(..., description="Initial payload / binary observed")
    firstObserved: str = Field(..., description="First observation timestamp")
    primary: Optional[str] = None
    confidence: Optional[float] = None
    confidence_status: Optional[str] = None
    confidenceStatus: Optional[str] = None
    requires_analyst_verification: Optional[bool] = None
    requiresAnalystVerification: Optional[bool] = None
    reasoning: Optional[str] = None
    contributingFactors: Optional[List[str]] = None


class RecommendedAction(BaseModel):
    id: str = Field(..., description="Action ID, e.g. ACT-01")
    title: str = Field(..., description="Short action summary")
    description: str = Field(..., description="Detailed instructions for responder")
    type: str = Field("CONTAINMENT", description="CONTAINMENT, ERADICATION, RECOVERY, HARDENING")
    status: str = Field("PENDING", description="PENDING, EXECUTING, COMPLETED, FAILED")
    target: str = Field(..., description="Target asset or credential")
    riskLevel: str = Field("HIGH", description="LOW, MED, HIGH")
    executedAt: Optional[str] = None
    executedBy: Optional[str] = None
    playbookId: Optional[str] = None


class TimelineEvent(BaseModel):
    id: str = Field(..., description="Event ID, e.g. EVT-01")
    timestamp: str = Field(..., description="Event timestamp (ISO)")
    relativeTime: str = Field("+00:00:00", description="Time offset relative to start")
    tactic: str = Field(..., description="MITRE tactic name")
    technique: str = Field(..., description="MITRE technique name")
    techniqueId: str = Field(..., description="MITRE technique ID")
    title: str = Field(..., description="Event title")
    description: str = Field(..., description="Event description")
    source: str = Field(..., description="Detection source / telemetry sensor")
    target: str = Field(..., description="Target host or entity")
    severity: str = Field("HIGH", description="Event severity")
    command: Optional[str] = None
    ioc: Optional[Dict[str, str]] = None
    evidenceConfidence: Optional[float] = None
    phaseOrder: int = 1


class AiAnalysisResult(BaseModel):
    analyzedAt: str = Field(..., description="Analysis completion timestamp")
    confidenceScore: float = Field(..., description="Neural correlation confidence (0-100)")
    threatClassification: str = Field(..., description="Identified threat campaign / actor")
    mitreCoverage: List[str] = Field(default_factory=list, description="List of MITRE technique IDs")
    keyFindings: List[str] = Field(default_factory=list, description="Synthesized forensic findings")
    killChainStage: str = Field(..., description="Current kill chain progression stage")
    blastRadius: str = Field(..., description="Assessed impact and perimeter boundaries")
    urgency: str = Field("IMMEDIATE", description="IMMEDIATE, HIGH, ELEVATED")
    suggestedContainmentSteps: List[str] = Field(default_factory=list, description="Recommended triage actions")
    summary: str = Field(..., description="Executive narrative summary")


# ---------------------------------------------------------------------------
# Canonical Incident Model
# ---------------------------------------------------------------------------
class Incident(BaseModel):
    id: str = Field(..., description="Incident ID, e.g. INC-8942")
    incident_id: Optional[str] = None
    title: str = Field(..., description="Incident title")
    severity: str = Field("HIGH", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    status: str = Field("ACTIVE", description="ACTIVE, TRIAGING, CONTAINED, MITIGATED, CLOSED")
    threatActor: str = Field("Unknown Threat Actor", description="Identified adversary group")
    threatActorOrigin: Optional[str] = Field(None, description="Adversary origin")
    detectedAt: str = Field(..., description="Detection timestamp")
    updatedAt: str = Field(..., description="Last updated timestamp")
    leadAnalyst: str = Field("Alexander Reyes (Lead)", description="Assigned SOC lead")
    impactSummary: str = Field(..., description="High-level impact assessment")
    affectedAssets: List[AffectedAsset] = Field(default_factory=list)
    rootCause: RootCause
    recommendedActions: List[RecommendedAction] = Field(default_factory=list)
    timelineEvents: List[TimelineEvent] = Field(default_factory=list)
    aiAnalysis: Optional[AiAnalysisResult] = None
    associatedAlertCount: int = Field(0, description="Total number of correlated alerts")
    alerts: Optional[List[Alert]] = Field(default_factory=list)
    riskScore: Optional[int] = Field(None, description="Deterministic risk score (0-100)")
    riskLevel: Optional[str] = Field(None, description="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    riskBreakdown: Optional[dict] = Field(default_factory=dict)
    # Canonical intelligence surfaces (populated by the intelligence pipeline)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    knowledgeGraph: Dict[str, Any] = Field(default_factory=dict)
    threatIntelligence: Dict[str, Any] = Field(default_factory=dict)
    workflowIntelligence: Dict[str, Any] = Field(default_factory=dict)
    businessImpact: Dict[str, Any] = Field(default_factory=dict)
    predictions: List[Dict[str, Any]] = Field(default_factory=list)
    confidenceAssessment: Dict[str, Any] = Field(default_factory=dict)
    confidenceContract: Dict[str, Any] = Field(default_factory=dict)
    decisionRecommendations: List[Dict[str, Any]] = Field(default_factory=list)
    latestSimulation: Dict[str, Any] = Field(default_factory=dict)
    assetDependencies: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)
    digitalTwinSnapshots: List[Dict[str, Any]] = Field(default_factory=list)
    incidentMemory: Dict[str, Any] = Field(default_factory=dict)
    lastDecision: Dict[str, Any] = Field(default_factory=dict)
    approvalState: Dict[str, Any] = Field(default_factory=dict)
    lastApprovedPlaybook: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(populate_by_name=True, extra="allow")


# ---------------------------------------------------------------------------
# KPI & Response Models
# ---------------------------------------------------------------------------
class KpiMetrics(BaseModel):
    data_classification: str = Field("calculated", description="KPI provenance label: calculated, estimated, observed, simulated, or demo")
    activeIncidents: int
    criticalAlerts: int
    mttdMinutes: float
    mttrMinutes: float
    threatLevel: str
    compromisedAssets: int
    blockedAttacks24h: int


class IncidentsResponse(BaseModel):
    incidents: List[Incident]
    kpis: KpiMetrics
    timestamp: str


class AlertsResponse(BaseModel):
    alerts: List[Alert]
    total: int
    timestamp: str


class AnalyzeRequest(BaseModel):
    incidentId: str
    analystNotes: Optional[str] = None
    includeTelemetryPcap: Optional[bool] = False


class AnalyzeResponse(BaseModel):
    success: bool
    analysis: AiAnalysisResult
    updatedIncident: Incident


class SimulateRequest(BaseModel):
    scenario: str = Field("ransomware", description="Attack scenario name")
    seed: Optional[int] = None
    post_to_backend: Optional[bool] = True


class StatusUpdateRequest(BaseModel):
    status: str


class DashboardMetrics(BaseModel):
    """Canonical /api/dashboard contract — every value is derived from real
    persisted repository state; ``None`` means the metric is genuinely
    unavailable (frontend must render an explicit unavailable state, never
    fabricate a number).

    Semantics:
    - activeIncidents  : incidents in ACTIVE/TRIAGING/CONTAINED/ACTIVE_CONTAINMENT
    - totalAlerts      : persisted alert (event) count for the workspace
    - incidentSeverity : severity histogram over workspace incidents
    - incidentStatus   : status histogram over workspace incidents
    - eventsProcessed  : persisted event records (events and alerts share the
                         same persisted record set in this pipeline)
    - sensorSources    : distinct persisted telemetry ``source`` values; None
                         when no telemetry sources exist
    - ingestionRate    : events/sec computed from persisted event timestamps
                         in the trailing 300s window; None when the window has
                         no events (insufficient telemetry)
    - mttdMinutes      : mean time to detection from persisted timestamps;
                         None when timestamps are insufficient
    - mttcMinutes      : mean time to containment from persisted timestamps;
                         None when timestamps are insufficient
    - bufferUtilization: always None — no backend queue/buffer metric exists
    - sensorHealth     : always None — no real sensor health telemetry collected
    - generatedAt      : server clock time of the response
    """
    activeIncidents: int
    totalAlerts: int
    incidentSeverity: dict[str, int] = {}
    incidentStatus: dict[str, int] = {}
    eventsProcessed: int = 0
    sensorSources: int | None = None
    ingestionRate: float | None = None
    mttdMinutes: float | None = None
    mttcMinutes: float | None = None
    bufferUtilization: float | None = None
    sensorHealth: str | None = None
    generatedAt: str = ""
