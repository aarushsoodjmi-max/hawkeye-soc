/**
 * HawkEye SOC — Real-Time WebSocket Client
 * ==========================================
 * Connects to the tenant-isolated /ws endpoint with JWT authentication.
 * Handles auto-reconnect, exponential backoff, ping/pong heartbeats,
 * and topic-based dispatching.
 */

export type WsConnectionStatus = 'CONNECTING' | 'OPEN' | 'CLOSED' | 'RECONNECTING' | 'DISCONNECTED';

export interface WsMessage {
  topic?: string;
  type?: string;
  data?: unknown;
  event_type?: string;
  incident_id?: string;
  timestamp?: string;
  [key: string]: unknown;
}

type MessageHandler = (msg: WsMessage) => void;
type StatusHandler = (status: WsConnectionStatus) => void;

export class HawkeyeWebSocketClient {
  private ws: WebSocket | null = null;
  private url: string = '';
  private token: string | null = null;
  private status: WsConnectionStatus = 'CLOSED';
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectTimer: number | null = null;
  private pingInterval: number | null = null;
  private listeners: Map<string, Set<MessageHandler>> = new Map();
  private statusListeners: Set<StatusHandler> = new Set();
  private isExplicitlyClosed = false;

  constructor() {
    this.setupUrl();
  }

  private setupUrl() {
    const configured = import.meta.env.VITE_WS_URL as string | undefined;
    if (!configured) {
      throw new Error('Configuration error: VITE_WS_URL is not set. The frontend refuses to derive a default WebSocket URL. Export VITE_WS_URL explicitly (e.g. ws://localhost:8000/ws).');
    }
    this.url = configured.replace(/\/+$/, '');
  }

  public setCustomBaseUrl(httpUrl: string) {
    if (!httpUrl) {
      // Keep the explicitly configured VITE_WS_URL; never derive a fallback.
      return;
    }
    const wsUrl = httpUrl.replace(/^http/, 'ws');
    this.url = `${wsUrl}/ws`;
    if (this.status === 'OPEN' || this.status === 'CONNECTING') {
      this.disconnect();
      this.connect(this.token);
    }
  }

  public connect(token: string | null = null) {
    this.token = token;
    this.isExplicitlyClosed = false;

    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.setStatus('CONNECTING');

    const topics = [
      'event.normalized',
      'incident.updated',
      'risk.updated',
      'confidence.updated',
      'playbook.executed',
    ].join(',');

    const query = new URLSearchParams();
    if (token) query.set('token', token);
    query.set('topics', topics);

    const fullUrl = `${this.url}?${query.toString()}`;

    try {
      this.ws = new WebSocket(fullUrl);

      this.ws.onopen = () => {
        this.setStatus('OPEN');
        this.reconnectAttempts = 0;
        this.startHeartbeat();
      };

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          const data: WsMessage = JSON.parse(event.data);
          this.handleIncomingMessage(data);
        } catch {
          // If non-JSON message, wrap as raw string
          this.handleIncomingMessage({ type: 'raw', data: event.data });
        }
      };

      this.ws.onclose = () => {
        this.stopHeartbeat();
        if (!this.isExplicitlyClosed) {
          this.scheduleReconnect();
        } else {
          this.setStatus('CLOSED');
        }
      };

      this.ws.onerror = () => {
        // Handled via onclose
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  public disconnect() {
    this.isExplicitlyClosed = true;
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.setStatus('CLOSED');
  }

  private scheduleReconnect() {
    if (this.isExplicitlyClosed) return;

    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      // Do NOT switch automatically to simulated telemetry - connected mode must clearly show DISCONNECTED
      this.setStatus('DISCONNECTED');
      return;
    }

    this.setStatus('RECONNECTING');
    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, this.reconnectAttempts), 15000);

    this.reconnectTimer = window.setTimeout(() => {
      this.connect(this.token);
    }, delay);
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.pingInterval = window.setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping', timestamp: new Date().toISOString() }));
      }
    }, 25000);
  }

  private stopHeartbeat() {
    if (this.pingInterval) {
      window.clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  private setStatus(status: WsConnectionStatus) {
    this.status = status;
    this.statusListeners.forEach((fn) => fn(status));
  }

  public getStatus(): WsConnectionStatus {
    return this.status;
  }

  public onStatusChange(handler: StatusHandler): () => void {
    this.statusListeners.add(handler);
    handler(this.status);
    return () => this.statusListeners.delete(handler);
  }

  public subscribe(topic: string, handler: MessageHandler): () => void {
    if (!this.listeners.has(topic)) {
      this.listeners.set(topic, new Set());
    }
    this.listeners.get(topic)!.add(handler);
    return () => {
      this.listeners.get(topic)?.delete(handler);
    };
  }

  private handleIncomingMessage(msg: WsMessage) {
    // Topic-specific handlers
    if (msg.topic && this.listeners.has(msg.topic)) {
      this.listeners.get(msg.topic)!.forEach((fn) => fn(msg));
    }
    // Wildcard listeners
    if (this.listeners.has('*')) {
      this.listeners.get('*')!.forEach((fn) => fn(msg));
    }
  }
}

export const wsClient = new HawkeyeWebSocketClient();
