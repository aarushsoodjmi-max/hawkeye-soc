/**
 * HawkEye SOC — canonical frontend state.
 *
 * This context is a thin client-side projection of backend state. It never
 * manufactures security records or substitutes local/demo data after an API
 * failure. Simulation is available only through explicit backend simulator
 * endpoints.
 */
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, ReactNode } from 'react';
import {
  Incident, Alert, SecurityEvent, AiModelProvider, AiResponse, Strategy,
  SimulationResponse, ActionComparison, ConfidenceResponse, PredictionResponse,
  KnowledgeGraphResponse, AffectedAsset, ExecutionHistory, ExecutiveReport,
  IncidentReport, AuditLogRecord, ToastMessage, StreamMetrics, PlaybookActionItem,
} from '../types';
import { api, ApiError } from '../services/api';
import { wsClient } from '../services/websocket';
import { useAuth } from './AuthContext';

export interface SocContextType {
  backendStatus: 'connected' | 'checking' | 'unavailable';
  backendUrl: string;
  setBackendUrl: (url: string) => void;
  checkBackendHealth: () => Promise<void>;
  dashboardMetrics: {
    activeIncidents: number;
    totalAlerts: number;
    incidentSeverity?: Record<string, number>;
    incidentStatus?: Record<string, number>;
    eventsProcessed?: number;
    sensorSources?: number | null;
    ingestionRate?: number | null;
    mttdMinutes?: number | null;
    mttcMinutes?: number | null;
    bufferUtilization?: number | null;
    sensorHealth?: string | null;
    generatedAt?: string;
  } | null;
  aiProvider: AiModelProvider;
  setAiProvider: (provider: AiModelProvider) => void;
  aiResponse: AiResponse | null;
  aiError: string | null;
  setAiError: (err: string | null) => void;
  isAiAnalyzing: boolean;
  requestAiAnalysis: (instructions?: string) => Promise<void>;
  incidents: Incident[];
  activeIncidentId: string;
  activeIncident: Incident | undefined;
  setActiveIncidentId: (id: string) => void;
  updateIncidentStatus: (incidentId: string, status: Incident['status']) => Promise<void>;
  toggleAssetIsolation: (incidentId: string, assetId: string) => Promise<void>;
  deployContainment: (directives: { isolateHosts: boolean; revokeTokens: boolean; bgpBlackhole: boolean; killProcesses: boolean }) => Promise<void>;
  queuePlaybookApproval: (actions: string[], target: string, title: string, impact?: string) => Promise<void>;
  events: SecurityEvent[];
  alerts: Alert[];
  isStreaming: boolean;
  setIsStreaming: (streaming: boolean) => void;
  clearEvents: () => void;
  metrics: StreamMetrics;
  assets: AffectedAsset[];
  quarantineAsset: (assetId: string) => void;
  restoreAsset: (assetId: string) => void;
  strategies: Strategy[];
  simulations: ActionComparison[];
  activeSimulation: SimulationResponse | null;
  isSimulating: boolean;
  runDecisionSimulation: (params?: { cascade_depth?: number; decay_factor?: number }) => Promise<void>;
  pendingApprovalAction: {
    playbookId: string; incidentId: string; actionDigest: string; title: string;
    target: string; impact: string; actionItem?: PlaybookActionItem;
  } | null;
  setPendingApprovalAction: (item: SocContextType['pendingApprovalAction']) => void;
  isApprovalModalOpen: boolean;
  setIsApprovalModalOpen: (open: boolean) => void;
  playbookHistories: ExecutionHistory[];
  activePlaybookSteps: PlaybookActionItem[];
  playbookExecutionState: 'IDLE' | 'SIMULATING' | 'PENDING_APPROVAL' | 'APPROVED' | 'EXECUTING' | 'COMPLETED' | 'FAILED';
  approvePendingAction: (approved?: boolean) => Promise<void>;
  rejectPendingAction: () => Promise<void>;
  executePlaybookStep: (actionId: string) => Promise<void>;
  executeFullPlaybook: (playbookId: string) => Promise<void>;
  knowledgeGraph: KnowledgeGraphResponse;
  traverseGraph: (entityId: string, depth?: number) => Promise<void>;
  prediction: PredictionResponse | null;
  confidence: ConfidenceResponse | null;
  executiveReport: ExecutiveReport | null;
  incidentReport: IncidentReport | null;
  exportReportJson: () => void;
  auditLog: AuditLogRecord[];
  toasts: ToastMessage[];
  addToast: (toast: Omit<ToastMessage, 'id' | 'timestamp'>) => void;
  removeToast: (id: string) => void;
  isDemoRunning: boolean;
  demoStage: string;
  runOneClickDemoScenario: () => Promise<void>;
  /** Display labels derived from backend AI health (configured Gemini model, Local mode). */
  aiModelLabels: { gemini: string; local: string; demo: string };
  aiModelProvider: AiModelProvider;
  setAiModelProvider: (provider: AiModelProvider) => void;
  loadScenario: (name?: string) => Promise<void>;
  scenarioRunning: boolean;
  containmentActive: boolean;
  setContainmentActive: (active: boolean) => void;
  toggleStreaming: () => void;
  clearEventsBuffer: () => void;
  injectTelemetryEvent: (event: SecurityEvent) => void;
  selectedEventId: string | null;
  setSelectedEventId: (id: string | null) => void;
  blockIp: (ip: string) => void;
  quarantineHost: (host: string) => void;
  correlateEventToIncident: (eventId: string) => void;
  pendingApproval: SocContextType['pendingApprovalAction'];
}

const emptyMetrics: StreamMetrics = {
  ingestionRate: null, peakRateChange: null, totalEventsToday: null,
  activeLogSources: null, totalLogSources: null, pipelineDropRate: null,
  errorPerSec: null, bufferPercent: null, bufferUsedGB: null, bufferMaxGB: null,
};
const emptyGraph: KnowledgeGraphResponse = { nodes: [], edges: [] };

function mapActionToVocabulary(action: string): string {
  const a = (action || '').toLowerCase();
  if (/(isolat|quarant|contain)/.test(a)) return 'isolate_device';
  if (/(block|blackhole|firewall|drop)/.test(a)) return 'block_ip';
  if (/(revoke|reset|credential|token|user|account|disable|password|mfa|session)/.test(a)) return 'disable_user';
  if (/(report|export|generate)/.test(a)) return 'generate_report';
  return 'create_ticket';
}

// Backend /api/ai/health shapes differ per provider: Gemini returns `model` as a
// string, the local provider returns it as an object with `model_name`.
const healthModelName = (h: any): string | null => {
  const m = h?.model;
  if (typeof m === 'string' && m.trim()) return m.trim();
  if (m && typeof m.model_name === 'string' && m.model_name.trim()) return m.model_name.trim();
  return null;
};

const DEFAULT_AI_LABELS = { gemini: 'Gemini', local: 'Local', demo: 'Deterministic Demo' };

const SocContext = createContext<SocContextType | undefined>(undefined);

export const SocProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { role, user, workspace, canExecuteActions, canApprovePlaybooks } = useAuth();
  const [backendStatus, setBackendStatus] = useState<SocContextType['backendStatus']>('checking');
  const [backendUrl, setBackendUrlState] = useState(api.getBaseUrl());
  const [aiProvider, setAiProviderState] = useState<AiModelProvider>(() =>
    (sessionStorage.getItem('hawkeye_ai_provider') as AiModelProvider) || (import.meta.env.VITE_DEMO_MODE === 'true' ? 'demo' : 'gemini')
  );
  const [dashboardMetrics, setDashboardMetrics] = useState<SocContextType['dashboardMetrics']>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [activeIncidentId, setActiveIncidentIdState] = useState('');
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [assets, setAssets] = useState<AffectedAsset[]>([]);
  const [metrics, setMetrics] = useState<StreamMetrics>(emptyMetrics);
  const [strategies, setStrategies] = useState<Strategy[]>([]);
  const [simulations, setSimulations] = useState<ActionComparison[]>([]);
  const [activeSimulation, setActiveSimulation] = useState<SimulationResponse | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [knowledgeGraph, setKnowledgeGraph] = useState<KnowledgeGraphResponse>(emptyGraph);
  const [prediction, setPrediction] = useState<PredictionResponse | null>(null);
  const [confidence, setConfidence] = useState<ConfidenceResponse | null>(null);
  const [executiveReport, setExecutiveReport] = useState<ExecutiveReport | null>(null);
  const [incidentReport, setIncidentReport] = useState<IncidentReport | null>(null);
  const [auditLog, setAuditLog] = useState<AuditLogRecord[]>([]);
  const [isStreaming, setIsStreaming] = useState(true);
  const [aiResponse, setAiResponse] = useState<AiResponse | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [isAiAnalyzing, setIsAiAnalyzing] = useState(false);
  const [pendingApprovalAction, setPendingApprovalAction] = useState<SocContextType['pendingApprovalAction']>(null);
  const [isApprovalModalOpen, setIsApprovalModalOpen] = useState(false);
  const [playbookHistories, setPlaybookHistories] = useState<ExecutionHistory[]>([]);
  const [activePlaybookSteps, setActivePlaybookSteps] = useState<PlaybookActionItem[]>([]);
  const [playbookExecutionState, setPlaybookExecutionState] = useState<SocContextType['playbookExecutionState']>('IDLE');
  const [isDemoRunning, setIsDemoRunning] = useState(false);
  const [demoStage, setDemoStage] = useState('');
  const [scenarioRunning, setScenarioRunning] = useState(false);

  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);

  // De-dup guard: only fire the "backend unavailable" toast once per outage,
  // not on every polling cycle. Reset when the backend comes back online.
  const backendUnavailableToastedRef = useRef(false);

  const addToast = useCallback((toast: Omit<ToastMessage, 'id' | 'timestamp'>) => {
    const id = `toast-${Date.now()}-${crypto.randomUUID?.() || Date.now()}`;
    const message: ToastMessage = {
      ...toast,
      id,
      timestamp: new Date().toLocaleTimeString(),
      durationMs: toast.durationMs || 3000,
    };
    setToasts(prev => [message, ...prev.slice(0, 7)]);
    // Every toast auto-dismisses after 3 seconds; the queue keeps independently
    // timed entries while manual dismissal still works.
    window.setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, message.durationMs);
  }, []);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const removeToast = useCallback((id: string) => setToasts(prev => prev.filter(t => t.id !== id)), []);

  const activeIncident = incidents.find(i => i.id === activeIncidentId);

  const setActiveIncidentId = useCallback((id: string) => {
    if (!incidents.some(i => i.id === id)) {
      addToast({ title: 'Incident Not Found', description: `Incident ${id} is not present in backend state.`, type: 'error' });
      return;
    }
    setActiveIncidentIdState(id);
  }, [incidents, addToast]);

  // Refs keep hydrateIncident/hydrateAll referentially stable. Previously they
  // depended on `incidents` / `activeIncidentId`, so every hydration changed their
  // identity, which re-ran the WebSocket subscription and hydration effects and
  // produced a continuous request/render loop.
  const incidentsRef = useRef<Incident[]>([]);
  useEffect(() => { incidentsRef.current = incidents; }, [incidents]);
  const activeIncidentIdRef = useRef('');
  useEffect(() => { activeIncidentIdRef.current = activeIncidentId; }, [activeIncidentId]);
  // In-flight de-duplication: concurrent callers share one request round.
  const incidentInflightRef = useRef<Map<string, Promise<void>>>(new Map());
  const hydrateAllInflightRef = useRef<Promise<boolean> | null>(null);

  const hydrateIncident = useCallback((id: string): Promise<void> => {
    if (!id) return Promise.resolve();
    const existing = incidentInflightRef.current.get(id);
    if (existing) return existing;
    const run = hydrateIncidentImpl(id).finally(() => { incidentInflightRef.current.delete(id); });
    incidentInflightRef.current.set(id, run);
    return run;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function hydrateIncidentImpl(id: string): Promise<void> {
    const results = await Promise.allSettled([
      api.getPrediction(id), api.getConfidence(id), api.getExecutiveReport(id),
      api.getIncidentReport(id), api.getPlaybookHistory(id), api.getStrategies(id),
    ]);
    const [pred, conf, exec, report, history, strat] = results;
    setPrediction(pred.status === 'fulfilled' ? pred.value : null);
    setConfidence(conf.status === 'fulfilled' ? conf.value : null);
    setExecutiveReport(exec.status === 'fulfilled' ? exec.value : null);
    setIncidentReport(report.status === 'fulfilled' ? report.value : null);
    if (history.status === 'fulfilled') {
      const h = Array.isArray(history.value) ? history.value : [];
      setPlaybookHistories(h);
      const latest = h[0];
      if (latest?.actions?.length) setActivePlaybookSteps(latest.actions);
      else {
        const inc = incidentsRef.current.find(i => i.id === id);
        setActivePlaybookSteps((inc?.recommendedActions || []).map(a => ({
          id: a.id, action_type: a.title, target: a.target, status: a.status === 'APPROVED' ? 'PENDING' : a.status,
          description: a.description, executed_at: a.executedAt, executed_by: a.executedBy, verified: undefined,
        })));
      }
    } else setPlaybookHistories([]);
    if (strat.status === 'fulfilled') {
      setStrategies(Array.isArray(strat.value?.strategies) ? strat.value.strategies : []);
    } else setStrategies([]);
  }

  const hydrateAllImpl = async (): Promise<boolean> => {
    const [dash, inc, evt, alt, ast, graph, audit] = await Promise.allSettled([
      api.getDashboardMetrics(), api.getIncidents(), api.getEvents(), api.getAlerts(), api.getAssets(),
      api.getKnowledgeGraph(), api.getAuditLog(),
    ]);
    const failures = [dash, inc, evt, alt, ast, graph, audit].filter(r => r.status === 'rejected');
    if (dash.status === 'fulfilled') {
      setDashboardMetrics(dash.value);
      // Stream metrics are backend-derived only; every unavailable field stays
      // null and the UI renders an explicit unavailable state.
      setMetrics({
        ingestionRate: dash.value.ingestionRate ?? null,
        peakRateChange: null,
        totalEventsToday: dash.value.eventsProcessed ?? null,
        activeLogSources: dash.value.sensorSources ?? null,
        totalLogSources: dash.value.sensorSources ?? null,
        pipelineDropRate: null,
        errorPerSec: null,
        bufferPercent: null,
        bufferUsedGB: null,
        bufferMaxGB: null,
      });
    } else setDashboardMetrics(null);
    if (inc.status === 'fulfilled') {
      const list = inc.value.incidents || [];
      setIncidents(list);
      const selected = activeIncidentIdRef.current;
      const current = list.some(x => x.id === selected) ? selected : (list[0]?.id || '');
      setActiveIncidentIdState(current);
      if (current) await hydrateIncident(current);
      else {
        setPrediction(null); setConfidence(null); setExecutiveReport(null); setIncidentReport(null);
        setActivePlaybookSteps([]); setPlaybookHistories([]); setStrategies([]);
      }
    } else setIncidents([]);
    if (evt.status === 'fulfilled') setEvents(evt.value); else setEvents([]);
    if (alt.status === 'fulfilled') setAlerts(alt.value.alerts || []); else setAlerts([]);
    if (ast.status === 'fulfilled') setAssets(ast.value); else setAssets([]);
    if (graph.status === 'fulfilled') setKnowledgeGraph(graph.value); else setKnowledgeGraph(emptyGraph);
    if (audit.status === 'fulfilled') setAuditLog(audit.value.records || []); else setAuditLog([]);
    if (dash.status !== 'fulfilled') setMetrics(emptyMetrics);
    return failures.length === 0;
  };

  // Concurrent callers share the in-flight round. A caller arriving mid-flight
  // (e.g. right after a user action) is coalesced into ONE trailing round, so it
  // never gets pre-action data and a burst never fans out into many rounds.
  const hydrateAllQueuedRef = useRef<Promise<boolean> | null>(null);
  const hydrateAll = useCallback((): Promise<boolean> => {
    const start = (): Promise<boolean> => {
      const run: Promise<boolean> = hydrateAllImpl().finally(() => {
        if (hydrateAllInflightRef.current === run) hydrateAllInflightRef.current = null;
      });
      hydrateAllInflightRef.current = run;
      return run;
    };
    const inflight = hydrateAllInflightRef.current;
    if (!inflight) return start();
    if (!hydrateAllQueuedRef.current) {
      hydrateAllQueuedRef.current = inflight.catch(() => false).then(() => {
        hydrateAllQueuedRef.current = null;
        return start();
      });
    }
    return hydrateAllQueuedRef.current;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hydrateIncident]);

  // Keep a stable ref to hydrateAll so checkBackendHealth never re-creates
  // just because activeIncidentId changed — that was causing the health check
  // effect to re-fire and reset all state on every incident selection.
  const hydrateAllRef = useRef(hydrateAll);
  useEffect(() => { hydrateAllRef.current = hydrateAll; }, [hydrateAll]);
  const hydrateIncidentRef = useRef(hydrateIncident);
  useEffect(() => { hydrateIncidentRef.current = hydrateIncident; }, [hydrateIncident]);
  const addToastRef = useRef(addToast);
  useEffect(() => { addToastRef.current = addToast; }, [addToast]);

  const checkBackendHealth = useCallback(async () => {
    setBackendStatus('checking');
    try {
      const health = await api.getHealth();
      if (!health?.status) throw new Error('Invalid backend health response');
      setBackendStatus('connected');
      backendUnavailableToastedRef.current = false;
      await hydrateAllRef.current();
    } catch (err: any) {
      setBackendStatus('unavailable');
      setDashboardMetrics(null); setIncidents([]); setEvents([]); setAlerts([]); setAssets([]);
      setKnowledgeGraph(emptyGraph); setPrediction(null); setConfidence(null);
      setExecutiveReport(null); setIncidentReport(null); setStrategies([]); setActivePlaybookSteps([]);
      if (!backendUnavailableToastedRef.current) {
        backendUnavailableToastedRef.current = true;
        addToast({ title: 'BACKEND UNAVAILABLE', description: err?.message || 'FastAPI backend is unavailable.', type: 'error' });
      }
    }
  }, [addToast]);

  useEffect(() => { checkBackendHealth(); }, [checkBackendHealth, user?.sub, workspace]);

  useEffect(() => {
    if (!activeIncidentId || backendStatus !== 'connected') return;
    hydrateIncident(activeIncidentId);
  }, [activeIncidentId, backendStatus, hydrateIncident]);

  // Realtime updates are preserved, but event-driven hydration is debounced
  // (~400ms) and coalesced: a burst of WebSocket messages produces at most one
  // hydrateAll, and incident-scoped topics are folded into it when one is pending.
  // The subscription is registered once and reads current state through refs, so
  // hydration results can never re-trigger the subscription.
  useEffect(() => {
    const HYDRATE_DEBOUNCE_MS = 400;
    let allTimer: number | null = null;
    let incidentTimer: number | null = null;

    const scheduleAll = () => {
      if (incidentTimer !== null) { window.clearTimeout(incidentTimer); incidentTimer = null; }
      if (allTimer !== null) window.clearTimeout(allTimer);
      allTimer = window.setTimeout(() => { allTimer = null; void hydrateAllRef.current(); }, HYDRATE_DEBOUNCE_MS);
    };
    const scheduleIncident = () => {
      if (allTimer !== null) return; // the pending full hydration already covers the active incident
      if (incidentTimer !== null) window.clearTimeout(incidentTimer);
      incidentTimer = window.setTimeout(() => {
        incidentTimer = null;
        const id = activeIncidentIdRef.current;
        if (id) void hydrateIncidentRef.current(id);
      }, HYDRATE_DEBOUNCE_MS);
    };

    const unsub = wsClient.onStatusChange(status => {
      if (status === 'DISCONNECTED') addToastRef.current({ title: 'WebSocket Disconnected', description: 'Live updates paused; no synthetic telemetry will be generated.', type: 'error' });
    });
    const unsubs = [
      wsClient.subscribe('event.normalized', scheduleAll),
      wsClient.subscribe('incident.updated', scheduleAll),
      wsClient.subscribe('risk.updated', scheduleIncident),
      wsClient.subscribe('confidence.updated', scheduleIncident),
      wsClient.subscribe('playbook.executed', scheduleIncident),
    ];
    return () => {
      unsub(); unsubs.forEach(fn => fn());
      if (allTimer !== null) window.clearTimeout(allTimer);
      if (incidentTimer !== null) window.clearTimeout(incidentTimer);
    };
  }, []);

  // Model labels come from the backend's configured models, not hard-coded names.
  const [aiModelLabels, setAiModelLabels] = useState(DEFAULT_AI_LABELS);
  useEffect(() => {
    if (backendStatus !== 'connected') { setAiModelLabels(DEFAULT_AI_LABELS); return; }
    let cancelled = false;
    (async () => {
      const [g, l, d] = await Promise.allSettled([api.getAiHealth('gemini'), api.getAiHealth('local'), api.getAiHealth('demo')]);
      if (cancelled) return;
      let gemini = DEFAULT_AI_LABELS.gemini;
      if (g.status === 'fulfilled') {
        const name = healthModelName(g.value) || 'Gemini';
        gemini = String((g.value as any)?.status) === 'unconfigured' ? `${name} (not configured)` : name;
      } else gemini = 'Gemini (unavailable)';
      let local = DEFAULT_AI_LABELS.local;
      if (l.status === 'fulfilled') {
        const name = healthModelName(l.value) || 'Local model';
        local = String((l.value as any)?.status) === 'ok' ? `${name} (Local)` : `${name} (Local · offline)`;
      } else local = 'Local (unavailable)';
      const demo = d.status === 'fulfilled' ? (healthModelName(d.value) || 'Deterministic Demo') : 'Deterministic Demo';
      setAiModelLabels({ gemini, local, demo });
    })();
    return () => { cancelled = true; };
  }, [backendStatus, user?.sub, workspace]);

  const setAiProvider = useCallback((provider: AiModelProvider) => {
    sessionStorage.setItem('hawkeye_ai_provider', provider);
    setAiProviderState(provider);
  }, []);

  const requestAiAnalysis = useCallback(async (instructions?: string) => {
    if (!activeIncidentId) {
      setAiError('No backend incident is selected.');
      return;
    }
    setIsAiAnalyzing(true); setAiError(null);
    try {
      const resp = await api.analyzeWithAi({ incident_id: activeIncidentId, task: 'analysis', analyst_instructions: instructions, provider: aiProvider });
      setAiResponse(resp);
    } catch (err: any) {
      setAiResponse(null);
      setAiError(err?.message || 'AI provider unavailable.');
      addToast({ title: 'AI ANALYSIS FAILED', description: err?.message || 'AI provider unavailable.', type: 'error' });
    } finally { setIsAiAnalyzing(false); }
  }, [activeIncidentId, aiProvider, addToast]);

  const updateIncidentStatus = useCallback(async (id: string, status: Incident['status']) => {
    // Optimistic update — flip immediately so the button responds instantly
    const prev_status = incidents.find(i => i.id === id)?.status;
    setIncidents(prev => prev.map(i => i.id === id ? { ...i, status } : i));
    try {
      const updated = await api.updateIncidentStatus(id, status);
      // Reconcile with backend response but preserve status from backend
      setIncidents(prev => prev.map(i => i.id === id ? updated : i));
      // Do NOT hydrateIncident here — it would overwrite the optimistic update
      // with a stale backend response before the DB has committed the change
    } catch (err: any) {
      // Revert to previous status on failure
      setIncidents(prev => prev.map(i => i.id === id ? { ...i, status: prev_status ?? i.status } : i));
      addToast({ title: 'STATUS UPDATE FAILED', description: err?.message || 'Backend update failed.', type: 'error' });
    }
  }, [incidents, activeIncidentId, addToast]);

  const toggleAssetIsolation = useCallback(async (incidentId: string, assetId: string) => {
    if (!canExecuteActions) { addToast({ title: 'Action Prohibited by RBAC', description: 'Operator or Admin privileges are required.', type: 'error' }); return; }
    try {
      const updated = await api.toggleAssetIsolation(incidentId, assetId);
      setIncidents(prev => prev.map(i => i.id === incidentId ? updated : i));
      const updatedAsset = (updated.affectedAssets || []).find(x => x.id === assetId);
      if (updatedAsset) setAssets(prev => prev.map(a => a.id === assetId ? updatedAsset : a));
      await hydrateIncident(incidentId);
    } catch (err: any) {
      addToast({ title: 'ASSET ACTION FAILED', description: err?.message || 'Backend action failed.', type: 'error' });
    }
  }, [canExecuteActions, hydrateIncident, addToast]);

  const runDecisionSimulation = useCallback(async (params?: { cascade_depth?: number; decay_factor?: number }) => {
    if (!activeIncidentId) return;
    setIsSimulating(true);
    try {
      const resp = await api.simulateDecision(activeIncidentId, params);
      setActiveSimulation(resp);
      addToast({ title: 'Simulation Complete', description: `${resp.cascading_affected_assets?.length || 0} affected assets returned by backend.`, type: 'success' });
      await hydrateIncident(activeIncidentId);
    } catch (err: any) {
      setActiveSimulation(null);
      addToast({ title: 'SIMULATION FAILED', description: err?.message || 'Backend simulation failed.', type: 'error' });
    } finally { setIsSimulating(false); }
  }, [activeIncidentId, hydrateIncident, addToast]);

  const executePlaybookStep = useCallback(async (actionId: string) => {
    const step = activePlaybookSteps.find(s => s.id === actionId);
    if (!step || !activeIncidentId) return;
    if (!canExecuteActions) { addToast({ title: 'Execution Denied', description: 'Operator or Admin privileges are required.', type: 'error' }); return; }
    try {
      setPlaybookExecutionState('SIMULATING');
      // Map frontend action_type labels to backend action strings.
      // Prefix-match handles dynamic titles like "Isolate Host WS-FIN-04"
      // and "Reset Credentials for Account carlos.patel".
      const resolveAction = (actionType: string): string => {
        const exact: Record<string, string> = {
          block_ip: 'block_ip',
          'Block IP': 'block_ip',
          disable_user: 'disable_user',
          'Disable User': 'disable_user',
          isolate_device: 'isolate_device',
          'Isolate Device': 'isolate_device',
          isolate_host: 'isolate_device',
          'Isolate Host': 'isolate_device',
          create_ticket: 'create_ticket',
          'Create Ticket': 'create_ticket',
          generate_report: 'generate_report',
          'Generate Report': 'generate_report',
          reset_credentials: 'disable_user',
          'Reset Credentials': 'disable_user',
          revoke_tokens: 'disable_user',
          'Revoke Tokens': 'disable_user',
          'Revoke Active': 'disable_user',
          block_c2: 'block_ip',
          'Block Adversary': 'block_ip',
          'Block Known': 'block_ip',
          'Block Tor': 'block_ip',
          contain: 'isolate_device',
          'Contain ': 'isolate_device',
        };
        if (exact[actionType]) return exact[actionType];
        // Prefix matching for dynamic titles
        const lower = actionType.toLowerCase();
        if (lower.startsWith('isolate')) return 'isolate_device';
        if (lower.startsWith('block') || lower.startsWith('deny')) return 'block_ip';
        if (lower.startsWith('reset') || lower.startsWith('revoke') || lower.startsWith('disable')) return 'disable_user';
        if (lower.startsWith('contain')) return 'isolate_device';
        if (lower.startsWith('generate') || lower.startsWith('report')) return 'generate_report';
        if (lower.startsWith('ticket') || lower.startsWith('create')) return 'create_ticket';
        // Fallback: pass the raw action_type string directly to the backend
        return actionType;
      };
      const action = resolveAction(step.action_type);
      const simulated = await api.simulatePlaybook(activeIncidentId, [action], step.target);
      const playbookId = simulated.playbook_id;
      if (!playbookId) throw new Error('Backend simulation did not return a playbook ID');
      setPendingApprovalAction({
        playbookId, incidentId: activeIncidentId, actionDigest: simulated.action_digest,
        title: step.description, target: step.target, impact: 'Backend-provided playbook simulation; review before approval.', actionItem: step,
      });
      setPlaybookExecutionState('PENDING_APPROVAL');
      setIsApprovalModalOpen(true);
      await hydrateIncident(activeIncidentId);
    } catch (err: any) {
      setPlaybookExecutionState('FAILED');
      addToast({ title: 'PLAYBOOK SIMULATION FAILED', description: err?.message || 'Backend playbook simulation failed.', type: 'error' });
    }
  }, [activePlaybookSteps, activeIncidentId, canExecuteActions, hydrateIncident, addToast]);

  const approvePendingAction = useCallback(async (approved = true) => {
    if (!pendingApprovalAction) return;
    if (!approved) return rejectPendingAction();
    if (!canApprovePlaybooks) { addToast({ title: 'Approval Denied', description: 'Admin or Analyst privileges are required.', type: 'error' }); return; }
    try {
      setIsApprovalModalOpen(false); setPlaybookExecutionState('APPROVED');
      await api.approvePlaybook(pendingApprovalAction.incidentId, pendingApprovalAction.playbookId, pendingApprovalAction.actionDigest);
      setPlaybookExecutionState('EXECUTING');
      const res = await api.executePlaybook(pendingApprovalAction.incidentId, pendingApprovalAction.playbookId);
      const incidentId = pendingApprovalAction.incidentId;
      setPendingApprovalAction(null);
      // Success is reported ONLY when the backend confirms the playbook was
      // executed and verified. Any other state (VERIFICATION_FAILED, FAILED, ...)
      // is surfaced as a failure with the actual state.
      if (res?.state === 'EXECUTED') {
        setPlaybookExecutionState('COMPLETED');
        addToast({ title: 'PLAYBOOK EXECUTED', description: 'Backend executed and verified the approved action.', type: 'success' });
      } else {
        const actualState = String(res?.state ?? res?.status ?? 'UNKNOWN');
        const detail = typeof (res as any)?.execution?.reason === 'string' ? ` — ${(res as any).execution.reason}` : '';
        setPlaybookExecutionState('FAILED');
        addToast({
          title: actualState === 'VERIFICATION_FAILED' ? 'PLAYBOOK VERIFICATION FAILED' : 'PLAYBOOK EXECUTION FAILED',
          description: `Backend reported state: ${actualState}${detail}`,
          type: 'error',
        });
      }
      await hydrateIncident(incidentId);
      await hydrateAll();
    } catch (err: any) {
      setPlaybookExecutionState('FAILED');
      addToast({ title: 'PLAYBOOK EXECUTION FAILED', description: err?.message || 'Backend execution/verification failed.', type: 'error' });
      await hydrateIncident(pendingApprovalAction.incidentId);
    }
  }, [pendingApprovalAction, canApprovePlaybooks, hydrateIncident, hydrateAll, addToast]);

  const rejectPendingAction = useCallback(async () => {
    if (!pendingApprovalAction) return;
    try {
      await api.rejectPlaybook(pendingApprovalAction.incidentId, pendingApprovalAction.playbookId, 'Rejected by operator');
      setPlaybookExecutionState('FAILED'); setIsApprovalModalOpen(false); setPendingApprovalAction(null);
      await hydrateIncident(pendingApprovalAction.incidentId); await hydrateAll();
    } catch (err: any) {
      addToast({ title: 'PLAYBOOK REJECTION FAILED', description: err?.message || 'Backend rejection failed.', type: 'error' });
    }
  }, [pendingApprovalAction, hydrateIncident, hydrateAll, addToast]);

  const executeFullPlaybook = useCallback(async (_playbookId: string) => {
    const pending = activePlaybookSteps.find(s => s.status === 'PENDING');
    if (pending) await executePlaybookStep(pending.id);
    else addToast({ title: 'No Pending Playbook Action', description: 'Backend returned no pending action for the selected incident.', type: 'info' });
  }, [activePlaybookSteps, executePlaybookStep, addToast]);

  const traverseGraph = useCallback(async (entityId: string, depth = 2) => {
    try {
      const result = await api.traverseKnowledgeGraph(entityId, depth);
      addToast({ title: 'Graph Traversal Complete', description: `${result.entities.length} entities returned by backend.`, type: 'info' });
    } catch (err: any) {
      addToast({ title: 'GRAPH TRAVERSAL FAILED', description: err?.message || 'Backend graph traversal failed.', type: 'error' });
    }
  }, [addToast]);

  const exportReportJson = useCallback(async () => {
    if (!activeIncidentId) return;
    try {
      const blob = await api.exportIncidentReport(activeIncidentId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `HawkEye_Incident_Report_${activeIncidentId}.json`; a.click(); URL.revokeObjectURL(url);
    } catch (err: any) {
      addToast({ title: 'REPORT EXPORT FAILED', description: err?.message || 'Backend report export failed.', type: 'error' });
    }
  }, [activeIncidentId, addToast]);

  const loadScenario = useCallback(async (name = 'ransomware') => {
    if (!user) { addToast({ title: 'Authentication Required', description: 'Authenticate with the backend before running a simulation.', type: 'error' }); return; }
    setScenarioRunning(true); setIsDemoRunning(true); setDemoStage(`Running scenario: ${name}...`);
    try {
      const result = await api.runSimulatorScenario(name);
      const incidentId = result.incidentId ? String(result.incidentId) : null;
      setDemoStage('Scenario complete — loading incident...');
      // Poll only /api/incidents (one cheap call) until the new incident appears.
      // Avoids the 7-call hydrateAll storm inside the retry loop.
      let confirmed = false;
      for (let attempt = 0; attempt < 5; attempt++) {
        await new Promise(r => setTimeout(r, 500));
        const fetched = await api.getIncidents().catch(() => ({ incidents: [] }));
        const list = fetched.incidents || [];
        if (!incidentId || list.some((i: any) => String(i.id) === incidentId)) {
          setIncidents(list);
          confirmed = true;
          break;
        }
      }
      // One full hydration now that the incident is confirmed in the DB
      await hydrateAll();
      if (incidentId) setActiveIncidentIdState(incidentId);
      addToast({ title: 'Attack Scenario Executed', description: `Simulated '${name}': ${(result as any).alertsCount ?? 0} alerts, incident ${incidentId || 'N/A'}.`, type: 'success' });
    } catch (err: any) {
      addToast({ title: 'SCENARIO FAILED', description: err?.message || 'Backend scenario failed.', type: 'error' });
    } finally { setScenarioRunning(false); setIsDemoRunning(false); setDemoStage(''); }
  }, [user, hydrateAll, addToast]);

  const runOneClickDemoScenario = useCallback(() => loadScenario('ransomware'), [loadScenario]);

  const toggleStreaming = useCallback(() => setIsStreaming(v => !v), []);
  const clearEventsBuffer = useCallback(async () => {
    try {
      const res = await api.clearEvents();
      await hydrateAll();
      addToast({ title: 'Telemetry Buffer Cleared', description: `Removed ${res.removed} unlinked event(s) from the workspace buffer.`, type: 'success' });
    } catch (err: any) {
      addToast({ title: 'CLEAR BUFFER FAILED', description: err?.message || 'Backend clear failed.', type: 'error' });
    }
  }, [hydrateAll, addToast]);
  const clearEvents = clearEventsBuffer;
  const injectTelemetryEvent = useCallback((_event: SecurityEvent) => {
    addToast({ title: 'Local telemetry injection blocked', description: 'Telemetry must enter through the backend simulator or ingestion API.', type: 'error' });
  }, [addToast]);
  const blockIp = useCallback(async (ip: string) => {
    if (!ip) return;
    if (!canExecuteActions) { addToast({ title: 'Action Prohibited by RBAC', description: 'Operator or Admin privileges are required.', type: 'error' }); return; }
    try {
      const res = await api.blockIp(ip);
      await hydrateAll();
      addToast({ title: 'Adversary IP Blocked', description: `Blocked ${ip} across ${res.affectedIncidentIds?.length || 0} incident(s).`, type: 'success' });
    } catch (err: any) {
      addToast({ title: 'IP BLOCK FAILED', description: err?.message || 'Backend block failed.', type: 'error' });
    }
  }, [canExecuteActions, hydrateAll, addToast]);
  const quarantineHost = useCallback(async (host: string) => {
    if (!host) return;
    if (!canExecuteActions) { addToast({ title: 'Action Prohibited by RBAC', description: 'Operator or Admin privileges are required.', type: 'error' }); return; }
    try {
      await api.quarantineHost(host);
      await hydrateAll();
      addToast({ title: 'Host Isolated', description: `Isolation directive applied to ${host}.`, type: 'success' });
    } catch (err: any) {
      addToast({ title: 'HOST ISOLATION FAILED', description: err?.message || 'Backend isolation failed.', type: 'error' });
    }
  }, [canExecuteActions, hydrateAll, addToast]);
  const correlateEventToIncident = useCallback(async (eventId: string) => {
    if (!eventId) return;
    try {
      const res = await api.correlateAlert(eventId);
      if (res.incidentId) {
        setActiveIncidentIdState(res.incidentId);
        await hydrateAll();
        addToast({ title: 'Event Correlated', description: `Alert ${eventId} linked to incident ${res.incidentId}.`, type: 'success' });
      } else {
        addToast({ title: 'Correlation No-Op', description: 'The alert is already linked to an incident.', type: 'info' });
      }
    } catch (err: any) {
      addToast({ title: 'CORRELATION FAILED', description: err?.message || 'Backend correlation failed.', type: 'error' });
    }
  }, [hydrateAll, addToast]);
  const deployContainment = useCallback(async (directives: { isolateHosts: boolean; revokeTokens: boolean; bgpBlackhole: boolean; killProcesses: boolean }) => {
    if (!activeIncidentId) { addToast({ title: 'No Incident Selected', description: 'Select an incident before deploying containment.', type: 'warning' }); return; }
    if (!canExecuteActions) { addToast({ title: 'Action Prohibited by RBAC', description: 'Operator or Admin privileges are required.', type: 'error' }); return; }
    // Optimistic update — flip to ACTIVE_CONTAINMENT immediately before the API round trip
    setIncidents(prev => prev.map(i => i.id === activeIncidentId ? { ...i, status: 'ACTIVE_CONTAINMENT' as const } : i));
    try {
      const updated = await api.containIncident(activeIncidentId, directives);
      // Reconcile with real backend response, then only re-hydrate the one incident
      setIncidents(prev => prev.map(i => i.id === activeIncidentId ? updated : i));
      await hydrateIncident(activeIncidentId);
      addToast({ title: 'Containment Executed', description: `Containment directives applied to ${updated.id}; status: ${updated.status}.`, type: 'success' });
    } catch (err: any) {
      // Revert optimistic status on failure
      setIncidents(prev => prev.map(i => i.id === activeIncidentId ? { ...i, status: 'ACTIVE' as const } : i));
      addToast({ title: 'CONTAINMENT FAILED', description: err?.message || 'Backend containment failed.', type: 'error' });
    }
  }, [activeIncidentId, canExecuteActions, hydrateIncident, addToast]);
  const queuePlaybookApproval = useCallback(async (actions: string[], target: string, title: string, impact?: string) => {
    if (!activeIncidentId) return;
    if (!canExecuteActions) { addToast({ title: 'Action Prohibited by RBAC', description: 'Operator or Admin privileges are required.', type: 'error' }); return; }
    setPlaybookExecutionState('SIMULATING');
    try {
      const canonical = (actions || []).map(mapActionToVocabulary);
      const simulated = await api.simulatePlaybook(activeIncidentId, canonical, target || activeIncidentId);
      if (!simulated.playbook_id) throw new Error('Backend simulation did not return a playbook ID');
      setPendingApprovalAction({
        playbookId: simulated.playbook_id,
        incidentId: activeIncidentId,
        actionDigest: simulated.action_digest,
        title,
        target: target || activeIncidentId,
        impact: impact || 'Backend-provided playbook simulation; review before approval.',
      });
      setPlaybookExecutionState('PENDING_APPROVAL');
      setIsApprovalModalOpen(true);
    } catch (err: any) {
      setPlaybookExecutionState('FAILED');
      addToast({ title: 'PLAYBOOK SIMULATION FAILED', description: err?.message || 'Backend playbook simulation failed.', type: 'error' });
    }
  }, [activeIncidentId, canExecuteActions, addToast]);

  const containmentActive = activeIncident?.status === 'CONTAINED' || activeIncident?.status === 'ACTIVE_CONTAINMENT';
  const setContainmentActive = useCallback((active: boolean) => {
    if (!activeIncidentId) return;
    void updateIncidentStatus(activeIncidentId, active ? 'CONTAINED' : 'ACTIVE').catch(() => undefined);
  }, [activeIncidentId, updateIncidentStatus]);

  const setBackendUrl = useCallback((url: string) => {
    api.setBaseUrl(url); wsClient.setCustomBaseUrl(url); setBackendUrlState(api.getBaseUrl()); void checkBackendHealth();
  }, [checkBackendHealth]);

  const value = useMemo<SocContextType>(() => ({
    backendStatus, backendUrl, setBackendUrl, checkBackendHealth, dashboardMetrics,
    aiProvider, setAiProvider, aiResponse, aiError, setAiError, isAiAnalyzing, requestAiAnalysis,
    incidents, activeIncidentId, activeIncident, setActiveIncidentId, updateIncidentStatus, toggleAssetIsolation,
    deployContainment, queuePlaybookApproval,
    events, alerts, isStreaming, setIsStreaming, clearEvents, metrics, assets,
    quarantineAsset: id => { void toggleAssetIsolation(activeIncidentId, id); },
    restoreAsset: id => { void toggleAssetIsolation(activeIncidentId, id); },
    strategies, simulations, activeSimulation, isSimulating, runDecisionSimulation,
    pendingApprovalAction, setPendingApprovalAction, isApprovalModalOpen, setIsApprovalModalOpen,
    playbookHistories, activePlaybookSteps, playbookExecutionState, approvePendingAction, rejectPendingAction,
    executePlaybookStep, executeFullPlaybook, knowledgeGraph, traverseGraph, prediction, confidence,
    executiveReport, incidentReport, exportReportJson, auditLog, toasts, addToast, removeToast,
    isDemoRunning, demoStage, runOneClickDemoScenario, aiModelLabels, aiModelProvider: aiProvider, setAiModelProvider: setAiProvider,
    loadScenario, scenarioRunning, containmentActive, setContainmentActive, toggleStreaming, clearEventsBuffer,
    injectTelemetryEvent, selectedEventId, setSelectedEventId, blockIp, quarantineHost, correlateEventToIncident,
    pendingApproval: pendingApprovalAction,
  }), [
    backendStatus, backendUrl, setBackendUrl, checkBackendHealth, dashboardMetrics, aiProvider, setAiProvider,
    aiResponse, aiError, isAiAnalyzing, requestAiAnalysis, incidents, activeIncidentId, activeIncident,
    setActiveIncidentId, updateIncidentStatus, toggleAssetIsolation, deployContainment, queuePlaybookApproval,
    events, alerts, isStreaming, metrics, assets,
    strategies, simulations, activeSimulation, isSimulating, runDecisionSimulation, pendingApprovalAction,
    isApprovalModalOpen, playbookHistories, activePlaybookSteps, playbookExecutionState, approvePendingAction,
    rejectPendingAction, executePlaybookStep, executeFullPlaybook, knowledgeGraph, traverseGraph, prediction,
    confidence, executiveReport, incidentReport, exportReportJson, auditLog, toasts, addToast, removeToast,
    isDemoRunning, demoStage, runOneClickDemoScenario, loadScenario, scenarioRunning, containmentActive,
    setContainmentActive, toggleStreaming, clearEventsBuffer, injectTelemetryEvent, selectedEventId,
    blockIp, quarantineHost, correlateEventToIncident,
  ]);

  return <SocContext.Provider value={value}>{children}</SocContext.Provider>;
};

export const useSoc = () => {
  const ctx = useContext(SocContext);
  if (!ctx) throw new Error('useSoc must be used within SocProvider');
  return ctx;
};
