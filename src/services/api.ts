/**
 * HawkEye SOC — Production Typed API Client
 * ==========================================
 * Fully integrates with Hawkeye V4.1.1 FastAPI Backend.
 * Automatically injects Bearer JWT authentication, workspace headers,
 * and typed error handling.
 */

import {
  Alert,
  Incident,
  AiAnalyzeRequest,
  AiResponse,
  AiHealth,
  AiModelInfo,
  StrategyResponse,
  SimulationResponse,
  ExecutionHistory,
  PlaybookActionItem,
  ConfidenceResponse,
  PredictionResponse,
  KnowledgeGraphResponse,
  GraphTraversalResponse,
  IncidentReport,
  ExecutiveReport,
  AuthTokenResponse,
  Principal,
  AffectedAsset,
  SecurityEvent,
  AuditLogRecord,
} from '../types';

export class ApiError extends Error {
  status: number;
  data: unknown;

  constructor(message: string, status: number, data?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

// Storage keys. The workspace is NOT persisted as a client-side override: it
// is always derived from the verified JWT claim (backend source of truth).
const TOKEN_KEY = 'hawkeye_jwt_token';

export class HawkeyeApiClient {
  private baseUrl: string;
  private token: string | null = null;
  private workspace: string = 'default';
  private onUnauthorized?: () => void;

  constructor() {
    const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;
    if (!configuredBaseUrl) {
      throw new Error('Configuration error: VITE_API_BASE_URL is not set. The frontend refuses to guess a backend URL. Export VITE_API_BASE_URL explicitly (e.g. http://localhost:8000).');
    }
    this.baseUrl = configuredBaseUrl.replace(/\/+$/, '');
    this.token = localStorage.getItem(TOKEN_KEY);
    // Workspace comes from the authenticated backend identity (JWT claim),
    // never trusted from client-side storage.
    this.workspace = 'default';
  }

  public setBaseUrl(url: string) {
    this.baseUrl = url.replace(/\/+$/, '');

  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  public setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  }

  public getToken(): string | null {
    return this.token;
  }

  public setWorkspace(workspace: string) {
    // Display/hint only: the backend derives the authoritative workspace from
    // the verified JWT and rejects any mismatch.
    this.workspace = workspace;
  }

  public getWorkspace(): string {
    return this.workspace;
  }

  public setOnUnauthorized(callback: () => void) {
    this.onUnauthorized = callback;
  }

  public decodePrincipal(): Principal | null {
    if (!this.token) return null;
    try {
      const parts = this.token.split('.');
      if (parts.length < 2) return null;
      const payload = JSON.parse(atob(parts[1]));
      return {
        sub: payload.sub || 'unknown',
        role: payload.role || 'viewer',
        workspace: payload.workspace || payload.workspace_id || this.workspace,
        user_id: payload.user_id || payload.sub || 'user',
        workspace_id: payload.workspace_id || payload.workspace || this.workspace,
        exp: payload.exp,
      };
    } catch {
      return null;
    }
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = this.baseUrl ? `${this.baseUrl}${endpoint}` : endpoint;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Workspace-ID': this.workspace,
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (response.status === 401) {
        if (this.onUnauthorized) {
          this.onUnauthorized();
        }
        throw new ApiError('Unauthorized session or token expired', 401);
      }

      if (response.status === 403) {
        throw new ApiError('Insufficient role privileges for this action', 403);
      }

      if (!response.ok) {
        let errData: unknown;
        try {
          errData = await response.json();
        } catch {
          errData = await response.text();
        }
        const detail =
          typeof errData === 'object' && errData && 'detail' in (errData as Record<string, unknown>)
            ? (errData as Record<string, unknown>).detail
            : undefined;
        // FastAPI's `detail` can be a plain string OR a structured error
        // object (e.g. AiError.to_payload() -> {code, message, details}).
        // String(obj) collapses the latter to the useless "[object Object]",
        // which is exactly what was surfacing in toasts/aiError — extract
        // the human-readable message field when present instead.
        let errorMsg: string;
        if (typeof detail === 'string') {
          errorMsg = detail;
        } else if (detail && typeof detail === 'object' && typeof (detail as Record<string, unknown>).message === 'string') {
          errorMsg = (detail as Record<string, unknown>).message as string;
        } else if (detail !== undefined) {
          try {
            errorMsg = JSON.stringify(detail);
          } catch {
            errorMsg = `Request failed with status ${response.status}`;
          }
        } else {
          errorMsg = `Request failed with status ${response.status}`;
        }
        throw new ApiError(errorMsg, response.status, errData);
      }

      // Handle 204 No Content
      if (response.status === 204) {
        return {} as T;
      }

      return await response.json();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        throw err;
      }
      throw new ApiError(
        (err as Error)?.message || 'Network request failed. Backend may be offline.',
        0,
        err
      );
    }
  }

  // -------------------------------------------------------------------------
  // 1. Authentication
  // -------------------------------------------------------------------------
  public async login(username: string, password: string, workspace = 'default'): Promise<AuthTokenResponse> {
    const res = await this.request<AuthTokenResponse>('/api/auth/token', {
      method: 'POST',
      body: JSON.stringify({ username, password, workspace }),
    });
    this.setToken(res.access_token);
    this.setWorkspace(workspace);
    return res;
  }

  public logout(): void {
    this.setToken(null);
  }

  // -------------------------------------------------------------------------
  // 2. Health & Status
  // -------------------------------------------------------------------------
  public async getHealth(): Promise<{ status: string; workspace?: string }> {
    return this.request<{ status: string; workspace?: string }>('/health');
  }

  public async getAuditLog(limit = 100): Promise<{ records: AuditLogRecord[] }> {
    return this.request<{ records: AuditLogRecord[] }>(`/api/audit?limit=${limit}`);
  }

  // -------------------------------------------------------------------------
  // 3. Incidents
  // -------------------------------------------------------------------------
  public async getIncidents(): Promise<{ incidents: Incident[]; total?: number; kpis?: any }> {
    const res = await this.request<{ incidents: Incident[]; total?: number; kpis?: any }>('/api/incidents');
    if (!res || !Array.isArray(res.incidents)) {
      throw new ApiError('Backend returned an invalid incidents response', 502, res);
    }
    return {
      incidents: res.incidents,
      total: res.total ?? res.incidents.length,
      kpis: res.kpis,
    };
  }

  public async getIncident(id: string): Promise<Incident> {
    if (!id) throw new ApiError('Incident ID is required', 400);
    return this.request<Incident>(`/api/incidents/${encodeURIComponent(id)}`);
  }

  public async updateIncidentStatus(id: string, status: string): Promise<Incident> {
    const res = await this.request<{ incident: Incident }>(`/api/incidents/${encodeURIComponent(id)}/status`, {
      method: 'PUT', body: JSON.stringify({ status }),
    });
    return res.incident;
  }

  public async executeIncidentAction(incidentId: string, actionId: string): Promise<Incident> {
    const res = await this.request<{ incident?: Incident }>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/execute`, { method: 'POST' });
    if (!res.incident) throw new ApiError('Backend did not return the updated incident', 502, res);
    return res.incident;
  }

  public async toggleAssetIsolation(incidentId: string, assetId: string): Promise<Incident> {
    const res = await this.request<{ incident?: Incident }>(`/api/incidents/${encodeURIComponent(incidentId)}/assets/${encodeURIComponent(assetId)}/toggle-isolation`, { method: 'POST' });
    if (!res.incident) throw new ApiError('Backend did not return the updated incident', 502, res);
    return res.incident;
  }

  public async containIncident(
    incidentId: string,
    directives: { isolateHosts?: boolean; revokeTokens?: boolean; bgpBlackhole?: boolean; killProcesses?: boolean }
  ): Promise<Incident> {
    const res = await this.request<{ incident: Incident }>(`/api/incidents/${encodeURIComponent(incidentId)}/contain`, {
      method: 'POST',
      body: JSON.stringify({ directives }),
    });
    return res.incident;
  }

  public async blockIp(ip: string): Promise<{ success: boolean; incidents?: Incident[]; affectedIncidentIds?: string[] }> {
    return this.request(`/api/containment/block-ip`, { method: 'POST', body: JSON.stringify({ ip }) });
  }

  public async quarantineHost(host: string): Promise<{ success: boolean; incident?: Incident }> {
    return this.request(`/api/containment/quarantine-host`, { method: 'POST', body: JSON.stringify({ host }) });
  }

  public async correlateAlert(alertId: string): Promise<{ success: boolean; incidentId?: string; incident?: Incident }> {
    return this.request(`/api/containment/correlate`, { method: 'POST', body: JSON.stringify({ alert_id: alertId }) });
  }

  public async clearEvents(): Promise<{ success: boolean; removed: number }> {
    return this.request(`/api/events/clear`, { method: 'POST' });
  }

  public async updateAlertStatus(alertId: string, status: string): Promise<{ message: string; alert: Alert }> {
    return this.request(`/api/alerts/${encodeURIComponent(alertId)}/status`, { method: 'PUT', body: JSON.stringify({ status }) });
  }

  // -------------------------------------------------------------------------
  // 4. Alerts
  // -------------------------------------------------------------------------
  public async getAlerts(params?: {
    severity?: string;
    status?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ alerts: Alert[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.status) query.set('status', params.status);
    if (params?.search) query.set('search', params.search);
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.offset) query.set('offset', String(params.offset));

    const qs = query.toString() ? `?${query.toString()}` : '';
    return this.request<{ alerts: Alert[]; total: number }>(`/api/alerts${qs}`);
  }

  public async getAlert(id: string): Promise<Alert> {
    return this.request<Alert>(`/api/alerts/${id}`);
  }

  public async getDashboardMetrics(): Promise<{
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
  }> {
    return this.request('/api/dashboard');
  }

  public async getEvents(limit: number = 100): Promise<SecurityEvent[]> {
    const res = await this.request<any>(`/api/events?limit=${limit}`);
    const raw = Array.isArray(res) ? res : res && Array.isArray(res.events) ? res.events : null;
    if (!raw) throw new ApiError('Backend returned an invalid events response', 502, res);
    // Backend alerts are mapped into the canonical SecurityEvent shape used by
    // the Live Event Stream (no synthetic telemetry is manufactured).
    return raw.map((a: any) => ({
      id: a.id || a.alert_id || '',
      timestamp: a.timestamp || '',
      severity: a.severity || 'LOW',
      source: a.source || a.category || 'EDR',
      eventType: a.title || a.event_type || a.alert_type || 'Security Alert',
      principal: a.user || a.username || 'unknown',
      sourceIp: a.sourceIp || a.src_ip || '0.0.0.0',
      sourceHost: a.host || a.hostname || undefined,
      destination: a.destinationIp || a.dst_ip || '0.0.0.0',
      correlatedIncident: a.incidentId || undefined,
      riskScore: a.confidenceScore ?? a.riskScore ?? undefined,
      contained: a.status === 'CONTAINED',
      blocked: a.status === 'CONTAINED',
      quarantined: a.status === 'CONTAINED',
      rawPayload: a.metadata || {},
    }));
  }

  // -------------------------------------------------------------------------
  // 5. AI Control & Investigation
  // -------------------------------------------------------------------------
  public async analyzeWithAi(req: AiAnalyzeRequest & { provider?: string }): Promise<AiResponse> {
    return this.request<AiResponse>('/api/ai/analyze', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  public async getAiHealth(provider?: string): Promise<AiHealth> {
    const q = provider ? `?provider=${encodeURIComponent(provider)}` : '';
    return this.request<AiHealth>(`/api/ai/health${q}`);
  }

  public async getAiModels(provider?: string): Promise<{ models: AiModelInfo[] }> {
    const q = provider ? `?provider=${encodeURIComponent(provider)}` : '';
    const res = await this.request<any>(`/api/ai/models${q}`);
    if (Array.isArray(res)) return { models: res };
    if (res && Array.isArray(res.models)) return res;
    throw new ApiError('Backend returned an invalid AI models response', 502, res);
  }

  // -------------------------------------------------------------------------
  // 6. Decision Center & Simulator
  // -------------------------------------------------------------------------
  public async getDecisionStrategies(incidentId: string): Promise<StrategyResponse> {
    return this.request<StrategyResponse>(`/api/decision/incidents/${incidentId}/strategies`);
  }

  public async getStrategies(incidentId: string): Promise<StrategyResponse> {
    return this.getDecisionStrategies(incidentId);
  }

  public async simulateDecision(
    incidentId: string,
    params?: { cascade_depth?: number; decay_factor?: number; max_depth?: number; decay?: number }
  ): Promise<SimulationResponse> {
    const query = new URLSearchParams();
    const depth = params?.max_depth ?? params?.cascade_depth;
    const decay = params?.decay ?? params?.decay_factor;
    if (depth !== undefined) query.set('max_depth', String(depth));
    if (decay !== undefined) query.set('decay', String(decay));
    const qs = query.toString() ? `?${query.toString()}` : '';

    return this.request<SimulationResponse>(
      `/api/decision-simulator/incidents/${incidentId}/simulate${qs}`,
      { method: 'POST' }
    );
  }

  // -------------------------------------------------------------------------
  // 7. Playbooks & Approval Engine
  // -------------------------------------------------------------------------
  public async simulatePlaybook(
    incidentId: string,
    actions: string[],
    target?: string
  ): Promise<{ status: string; playbook_id: string; simulation_id: string; actions: PlaybookActionItem[]; action_digest: string }> {
    return this.request<{ status: string; playbook_id: string; simulation_id: string; actions: PlaybookActionItem[]; action_digest: string }>(
      `/api/playbooks/incidents/${incidentId}/playbooks/simulate`,
      {
        method: 'POST',
        body: JSON.stringify({ actions, target }),
      }
    );
  }

  public async approvePlaybook(
    incidentId: string,
    playbookId: string,
    actionDigest?: string
  ): Promise<{ status: string; message: string }> {
    return this.request<{ status: string; message: string }>(
      `/api/playbooks/incidents/${incidentId}/playbooks/${playbookId}/approve`,
      {
        method: 'POST',
        body: JSON.stringify({ action_digest: actionDigest }),
      }
    );
  }

  public async rejectPlaybook(
    incidentId: string,
    playbookId: string,
    reason?: string
  ): Promise<{ status: string; message: string }> {
    return this.request<{ status: string; message: string }>(
      `/api/playbooks/incidents/${incidentId}/playbooks/${playbookId}/reject`,
      {
        method: 'POST',
        body: JSON.stringify({ reason }),
      }
    );
  }

  public async executePlaybook(
    incidentId: string,
    playbookId: string,
    actions?: PlaybookActionItem[] | string[],
    target?: string
  ): Promise<{ status: string; results?: unknown; state?: string; [key: string]: unknown }> {
    const actionStrings =
      actions?.map((a) => (typeof a === 'string' ? a : a.action_type || a.id || a.description)) || [];
    return this.request<{ status: string; results?: unknown; state?: string; [key: string]: unknown }>(
      `/api/playbooks/incidents/${incidentId}/playbooks/execute`,
      {
        method: 'POST',
        body: JSON.stringify({ playbook_id: playbookId, actions: actionStrings, target: target || incidentId }),
      }
    );
  }

  public async getPlaybookHistory(incidentId: string): Promise<ExecutionHistory[]> {
    return this.request<ExecutionHistory[]>(`/api/playbooks/incidents/${incidentId}/playbooks/history`);
  }

  // -------------------------------------------------------------------------
  // 8. Predictions & Confidence
  // -------------------------------------------------------------------------
  public async getPrediction(incidentId: string): Promise<PredictionResponse> {
    return this.request<PredictionResponse>(`/api/prediction/incidents/${incidentId}`);
  }

  public async getConfidence(incidentId: string): Promise<ConfidenceResponse> {
    return this.request<ConfidenceResponse>(`/api/confidence/incident/${incidentId}`);
  }

  // -------------------------------------------------------------------------
  // 9. Asset 360 Inventory
  // -------------------------------------------------------------------------
  public async getAssets(): Promise<AffectedAsset[]> {
    const res = await this.request<AffectedAsset[]>('/api/assets');
    if (!Array.isArray(res)) throw new ApiError('Backend returned an invalid assets response', 502, res);
    return res;
  }

  public async getAsset(assetId: string): Promise<AffectedAsset> {
    return this.request<AffectedAsset>(`/api/assets/${assetId}`);
  }

  // -------------------------------------------------------------------------
  // 10. Knowledge Graph
  // -------------------------------------------------------------------------
  public async getKnowledgeGraph(): Promise<KnowledgeGraphResponse> {
    return this.request<KnowledgeGraphResponse>('/api/graph');
  }

  public async traverseKnowledgeGraph(entityId: string, depth = 2): Promise<GraphTraversalResponse> {
    const q = new URLSearchParams({ entity_id: entityId, depth: String(depth) });
    return this.request<GraphTraversalResponse>(`/api/graph/traverse?${q.toString()}`);
  }

  // -------------------------------------------------------------------------
  // 11. Reporting
  // -------------------------------------------------------------------------
  public async getIncidentReport(incidentId: string): Promise<IncidentReport> {
    return this.request<IncidentReport>(`/api/reports/${incidentId}`);
  }

  public async getExecutiveReport(incidentId: string): Promise<ExecutiveReport> {
    return this.request<ExecutiveReport>(`/api/reports/${incidentId}/executive`);
  }

  public async exportIncidentReport(incidentId: string): Promise<Blob> {
    const url = this.baseUrl ? `${this.baseUrl}/api/reports/${incidentId}/export` : `/api/reports/${incidentId}/export`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: this.token ? `Bearer ${this.token}` : '',
        'X-Workspace-ID': this.workspace,
      },
    });
    if (!response.ok) {
      let errorMsg = response.statusText;
      try {
        const errorJson = await response.json();
        errorMsg = errorJson.detail || errorJson.message || errorMsg;
      } catch {
        // ignore
      }
      throw new ApiError(`Failed to export report: ${errorMsg}`, response.status);
    }
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = await response.json();
      if (data && data.success) {
        const fullReport = await this.getIncidentReport(incidentId);
        return new Blob([JSON.stringify(fullReport, null, 2)], { type: 'application/json' });
      }
      return new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    }
    return response.blob();
  }

  // -------------------------------------------------------------------------
  // 12. Simulator Scenarios
  // -------------------------------------------------------------------------
  public async runSimulatorScenario(scenario: string, seed?: number): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('/api/simulate', {
      method: 'POST',
      body: JSON.stringify({ scenario, seed, post_to_backend: true }),
    });
  }
}

// Export singleton instance
export const api = new HawkeyeApiClient();
