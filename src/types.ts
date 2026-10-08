export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ThemeMode = 'dark' | 'light';

export type Role = 'admin' | 'analyst' | 'operator' | 'viewer';

export type WorkspaceId = 'default' | 'finance-sec' | 'cloud-infra' | 'secops-core' | string;

export type AiModelProvider = 'gemini' | 'local' | 'demo';

export type NavTab =
  | 'overview'
  | 'live_events'
  | 'incidents'
  | 'alerts'
  | 'assets'
  | 'knowledge_graph'
  | 'risk_intel'
  | 'predictions'
  | 'decision_center'
  | 'response_strategies'
  | 'playbooks'
  | 'threat_intel'
  | 'reports'
  | 'simulator';

export interface Principal {
  sub: string;
  role: Role;
  workspace: string;
  user_id: string;
  workspace_id: string;
  exp?: number;
}

export interface AuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface SecurityContextDetail {
  title: string;
  description: string;
  type: 'mfa_bypass' | 'geoip_travel' | 'c2_beacon' | 'credential_dump' | 'dns_tunnel' | 'generic';
  details?: {
    origin?: string;
    destination?: string;
    speed?: string;
    anomalyScore?: string;
    hash?: string;
    mitreTactic?: string;
    mitreId?: string;
  };
}

export interface SecurityEvent {
  id: string;
  timestamp: string; // e.g. "08:42:15.892"
  timestampFull?: string;
  severity: Severity;
  source: string;
  eventType: string;
  principal: string;
  sourceIp: string;
  sourceHost?: string;
  destination: string;
  correlatedIncident?: string;
  riskScore?: number;
  unlinked?: boolean;
  agentVersion?: string;
  technique?: string;
  techniqueId?: string;
  securityContext?: SecurityContextDetail[];
  rawPayload: Record<string, unknown>;
  contained?: boolean;
  blocked?: boolean;
  quarantined?: boolean;
}

export interface StreamMetrics {
  ingestionRate: number | null; // eps
  peakRateChange: string | null;
  totalEventsToday: string | null;
  activeLogSources: number | null;
  totalLogSources: number | null;
  pipelineDropRate: string | null;
  errorPerSec: number | null;
  bufferPercent: number | null;
  bufferUsedGB: number | null;
  bufferMaxGB: number | null;
}

// ---------------------------------------------------------------------------
// Canonical Alert Model (Backend Parity)
// ---------------------------------------------------------------------------
export interface Alert {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  sourceIp: string;
  destinationIp: string;
  host: string;
  user: string;
  timestamp: string;
  mitreTactic: string;
  mitreTechnique: string;
  techniqueId: string;
  status: 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  incidentId?: string | null;
  confidenceScore: number;
  rawLog?: string | null;
  source?: string;
  description?: string;
  root_cause?: string;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Canonical Incident Sub-Models
// ---------------------------------------------------------------------------
export interface AffectedAsset {
  id: string;
  name: string;
  ip: string;
  os: string;
  role: string;
  status: 'COMPROMISED' | 'ISOLATED' | 'MONITORED' | 'CLEAN';
  criticality: 'TIER 0' | 'TIER 1' | 'TIER 2';
  dependencies?: string[];
  blastRadiusScore?: number;
}

export interface RootCause {
  vector: string;
  cveId?: string | null;
  cveScore?: number | null;
  entryPoint: string;
  compromisedAccount: string;
  c2Server: string;
  c2Location: string;
  vulnerabilityDetails: string;
  detectionMechanism: string;
  initialPayload: string;
  firstObserved: string;
  primary?: string;
  confidence?: number;
  confidence_status?: string;
  confidenceStatus?: string;
  requires_analyst_verification?: boolean;
  requiresAnalystVerification?: boolean;
  reasoning?: string;
  contributingFactors?: string[];
}

export interface RecommendedAction {
  id: string;
  title: string;
  description: string;
  type: 'CONTAINMENT' | 'ERADICATION' | 'RECOVERY' | 'HARDENING';
  status: 'PENDING' | 'EXECUTING' | 'COMPLETED' | 'FAILED' | 'REQUIRES_APPROVAL' | 'APPROVED' | 'REJECTED';
  target: string;
  riskLevel: 'LOW' | 'MED' | 'HIGH';
  executedAt?: string | null;
  executedBy?: string | null;
  playbookId?: string | null;
  requiresApproval?: boolean;
  impactScore?: number;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  relativeTime: string;
  tactic: string;
  technique: string;
  techniqueId: string;
  title: string;
  description: string;
  source: string;
  target: string;
  severity: Severity;
  command?: string | null;
  ioc?: Record<string, string> | null;
  evidenceConfidence: number;
  phaseOrder: number;
}

export interface AiAnalysisResult {
  analyzedAt: string;
  confidenceScore: number;
  threatClassification: string;
  mitreCoverage: string[];
  keyFindings: string[];
  killChainStage: string;
  blastRadius: string;
  urgency: 'IMMEDIATE' | 'HIGH' | 'ELEVATED';
  suggestedContainmentSteps: string[];
  summary: string;
}

// ---------------------------------------------------------------------------
// Canonical Incident Model
// ---------------------------------------------------------------------------
export interface Incident {
  id: string;
  incident_id?: string;
  title: string;
  description?: string;
  confidenceScore?: number;
  severity: Severity;
  status: 'ACTIVE' | 'TRIAGING' | 'CONTAINED' | 'MITIGATED' | 'CLOSED' | 'ACTIVE_CONTAINMENT' | 'INVESTIGATING';
  threatActor?: string;
  threatActorOrigin?: string | null;
  detectedAt?: string;
  containedAt?: string;
  updatedAt?: string;
  leadAnalyst?: string;
  assignedTo?: string;
  openedAt?: string;
  primaryVector?: string;
  impactedEntities?: {
    users?: string[];
    hosts?: string[];
    ips?: string[];
  };
  killChainStage?: string;
  mitreTechniques?: string[];
  autonomousActions?: {
    action: string;
    timestamp: string;
    status: string;
  }[];
  impactSummary?: string;
  affectedAssets?: AffectedAsset[];
  rootCause?: RootCause;
  recommendedActions?: RecommendedAction[];
  timelineEvents?: TimelineEvent[];
  aiAnalysis?: AiAnalysisResult | null;
  associatedAlertCount?: number;
  alerts?: Alert[];
  riskScore?: number | null;
  riskLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | null;
  riskBreakdown?: {
    asset_criticality?: number;
    exposure_factor?: number;
    threat_velocity?: number;
    blast_radius?: number;
    environmental_drift?: number;
  };
  metadata?: Record<string, unknown>;
  knowledgeGraph?: Record<string, unknown>;
  threatIntelligence?: Record<string, unknown>;
  workflowIntelligence?: Record<string, unknown>;
  businessImpact?: {
    estimated_downtime_minutes?: number;
    financial_impact_estimate?: string;
    compliance_impact?: string;
    data_classification?: 'calculated' | 'estimated' | 'observed' | 'simulated';
    critical_services_affected?: string[];
  };
  predictions?: PredictionResponse[];
  confidenceAssessment?: ConfidenceResponse;
  confidenceContract?: {
    version: string;
    subject_type: string;
    subject_id: string;
    unified_confidence: number;
    computed_at: string;
  };
  decisionRecommendations?: Strategy[];
  latestSimulation?: SimulationResponse;
  assetDependencies?: Record<string, (string | { asset_id?: string; id?: string; confidence?: number })[]>;
  digitalTwinSnapshots?: Record<string, unknown>[];
  incidentMemory?: Record<string, unknown>;
  lastDecision?: {
    generated_at: string;
    recommendations: Strategy[];
    decision_id: string;
  };
  approvalState?: {
    required: boolean;
    approved: boolean;
    status: 'SIMULATED' | 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'EXECUTING' | 'COMPLETED';
    playbook_id?: string;
    approved_by?: string;
    updated_at?: string;
    action_digest?: string;
  };
  lastApprovedPlaybook?: Record<string, unknown>;
}

export type IncidentRecord = Incident;

// ---------------------------------------------------------------------------
// AI Layer Contracts (Backend Parity)
// ---------------------------------------------------------------------------
export type ClaimBasis = 'observed' | 'inference' | 'prediction';

export interface SeverityAssessment {
  severity: Severity;
  justification: string;
  confidence: number;
}

export interface AttackPathStep {
  order: number;
  tactic: string;
  technique: string;
  techniqueId: string;
  source: string;
  target: string;
  description: string;
  confidence: number;
}

export interface PredictedNextStep {
  step: string;
  rationale: string;
  confidence: number;
  timeframe?: string | null;
}

export interface AiEvidenceReference {
  evidence_id: string;
  kind: string;
  summary: string;
  source: string;
  basis: ClaimBasis;
}

export interface PlaybookStep {
  sequence: number;
  action_type: string;
  target: string;
  description: string;
  owner_role?: string | null;
}

export interface AiAnalyzeRequest {
  incident_id: string;
  task?: string;
  provider?: string;
  analyst_instructions?: string | null;
  options?: {
    model?: string | null;
    temperature?: number | null;
    max_tokens?: number | null;
  } | null;
}

export interface ProposedPlaybook {
  playbook_id?: string | null;
  name: string;
  steps: PlaybookStep[];
  based_on?: string[];
}

export interface AiResponse {
  incident_id: string;
  task: string;
  generated_at: string;
  summary: string;
  severity_assessment?: SeverityAssessment | null;
  root_cause?: RootCause | null;
  attack_path: AttackPathStep[];
  affected_assets: AffectedAsset[];
  predicted_next_steps: PredictedNextStep[];
  predicted_next_action?: PredictedNextStep | null;
  recommendations: RecommendedAction[];
  risk?: {
    score: number;
    level: string;
    breakdown?: Record<string, number>;
  } | null;
  confidence: number;
  confidence_breakdown: Record<string, number>;
  evidence_references: AiEvidenceReference[];
  proposed_playbook?: ProposedPlaybook | null;
  mitre_techniques: string[];
  simulation_options: Record<string, unknown>[];
  approval_requirement: {
    required: boolean;
    mode: string;
    auto_execute: boolean;
  };
  reasoning: string;
  evidence_status: 'sufficient' | 'insufficient';
  validation_warnings: string[];
  requires_user_approval: boolean;
  auto_execute: boolean;
  raw_provider?: AiModelProvider;
  raw_model_name?: string;
  raw_payload?: Record<string, unknown>;
}

export interface AiHealth {
  status: string;
  provider: string;
  model: string;
  ready: boolean;
  latency_ms?: number;
}

export interface AiModelInfo {
  id: string;
  name: string;
  provider: AiModelProvider;
  context_window: number;
  is_default: boolean;
}

// ---------------------------------------------------------------------------
// Decision Engine & Decision Simulator Schemas
// ---------------------------------------------------------------------------
export interface Strategy {
  id: string;
  name: string;
  description: string;
  actions: string[];
  risk_reduction: number;
  downtime_hours: number;
  recovery_time_hours: number;
  operational_cost: number;
  confidence: number;
  rationale: string[];
  approval_required?: boolean;
  execution_state?: string;
}

export interface StrategyResponse {
  incident_id: string;
  strategies: Strategy[];
  generated_at: string;
}

export interface CascadeAsset {
  asset_id: string;
  hop_distance: number;
  decayed_impact: number;
  reason: string;
}

export interface RecoveryStep {
  asset_id: string;
  estimated_start_offset_hours: number;
  estimated_duration_hours: number;
}

export interface SimulationResponse {
  incident_id: string;
  cascade_depth: number;
  cascading_affected_assets: CascadeAsset[];
  affected_departments: string[];
  estimated_downtime_hours: number;
  recovery_time_hours: number;
  operational_cost: number;
  confidence_score: number;
  recovery_sequence: RecoveryStep[];
  containment_probability?: number;
  blast_radius_hosts?: number;
}

export interface ActionComparison {
  id: string;
  name: string;
  blastRadius: number; // hosts affected
  businessDisruption: number; // 0 - 100%
  containmentProbability: number; // 0 - 100%
  recoveryTimeHours: number;
  operationalCost: number;
  requiresApproval: boolean;
  actions: string[];
}

// ---------------------------------------------------------------------------
// Confidence Engine Schemas
// ---------------------------------------------------------------------------
export interface ConfidenceResponse {
  subject_type: string;
  subject_id: string;
  correlation_confidence: number;
  ml_confidence: number;
  threat_intel_confidence: number;
  data_quality_score: number;
  evidence_completeness_score: number;
  unified_confidence: number;
  unified_confidence_percent: number;
  confidence_partial: boolean;
  weights: Record<string, number>;
  breakdown: Record<string, unknown>;
  computed_at: string;
}

// ---------------------------------------------------------------------------
// Prediction Engine Schemas
// ---------------------------------------------------------------------------
export interface PredictedAsset {
  asset: string;
  reason: string;
  confidence: number;
}

export interface PredictionResponse {
  incident_id: string;
  generated_at: string;
  next_affected_assets: PredictedAsset[];
  lateral_movement: {
    probability?: number;
    predicted_target?: string;
    path?: string[];
  };
  downtime: {
    estimated_hours?: number;
    sla_breach_risk?: string;
  };
  affected_users: {
    privileged_accounts?: string[];
    risk_level?: string;
  };
  overall_confidence: number;
}

// ---------------------------------------------------------------------------
// Playbooks Schemas
// ---------------------------------------------------------------------------
export interface PlaybookActionItem {
  id: string;
  action_type: string;
  target: string;
  status: 'PENDING' | 'EXECUTING' | 'COMPLETED' | 'FAILED' | 'SIMULATED';
  executed_at?: string | null;
  executed_by?: string | null;
  result?: string | null;
  description: string;
  simulated_at?: string | null;
  verified?: boolean;
}

export interface ExecutionHistory {
  playbook_id: string;
  incident_id: string;
  workspace_id: string;
  actions: PlaybookActionItem[];
  state: 'SIMULATED' | 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'EXECUTING' | 'COMPLETED' | 'FAILED';
  simulation_id?: string | null;
  action_digest: string;
  approval: {
    approved_by?: string;
    approved_at?: string;
  };
  execution: {
    executed_by?: string;
    executed_at?: string;
    verified?: boolean;
  };
}

// ---------------------------------------------------------------------------
// Knowledge Graph Schemas
// ---------------------------------------------------------------------------
export interface GraphNode {
  id: string;
  type: 'asset' | 'user' | 'ip' | 'incident' | 'technique' | 'c2_server';
  name?: string;
  label?: string;
  status?: string;
  criticality?: string;
  riskScore?: number;
  properties?: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship_type: string;
  valid_from?: string | null;
  valid_to?: string | null;
  confidence: number;
}

export interface KnowledgeGraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphTraversalResponse {
  entity: string;
  depth: number;
  entities: string[];
  edges: GraphEdge[];
}

// ---------------------------------------------------------------------------
// Reporting Schemas
// ---------------------------------------------------------------------------
export interface IncidentReport {
  incident_id: string;
  title: string;
  description?: string;
  executive_summary?: string;
  attack_chain?: string[];
  affected_entities?: string[];
  root_cause?: string;
  confidence?: number;
  events?: {
    timestamp: string;
    technique: string;
    description: string;
  }[];
  generated_at?: string;
}

export interface ExecutiveReport {
  incident_id: string;
  workspace_id?: string;
  title?: string;
  status?: string;
  severity?: string;
  risk?: {
    score?: number;
    level?: string;
    breakdown?: Record<string, number>;
  };
  business_impact?: {
    estimated_downtime_minutes?: number;
    financial_impact_estimate?: string;
    compliance_impact?: string;
    critical_services_affected?: string[];
  } | Record<string, unknown>;
  prediction?: PredictionResponse | null;
  confidence?: ConfidenceResponse | null;
  executive_summary?: string;
  attack_chain?: string[];
  data_labels?: Record<string, string>;
  timeline?: TimelineEvent[];
  affected_assets?: AffectedAsset[];
  recommended_actions?: RecommendedAction[];
}

// ---------------------------------------------------------------------------
// Audit Log Record
// ---------------------------------------------------------------------------
export interface AuditLogRecord {
  id: string;
  timestamp: string;
  action: string;
  actorId: string;
  role: Role;
  workspaceId: string;
  outcome: 'SUCCESS' | 'FAILED' | 'PENDING' | 'REJECTED';
  details?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Toast Notification
// ---------------------------------------------------------------------------
export interface ToastMessage {
  id: string;
  title: string;
  description?: string;
  type: 'info' | 'success' | 'warning' | 'error' | 'critical';
  timestamp: string;
  durationMs?: number;
}
