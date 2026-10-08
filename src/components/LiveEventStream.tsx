import React, { useState, useEffect, useRef, useMemo } from 'react';
import { SecurityEvent, Severity, StreamMetrics, ThemeMode } from '../types';
import { EventContextDrawer } from './EventContextDrawer';

interface LiveEventStreamProps {
  events: SecurityEvent[];
  selectedEventId: string | null;
  onSelectEvent: (eventId: string) => void;
  onBlockIp: (ip: string) => void;
  onQuarantineHost: (host: string) => void;
  onCorrelateIncident: (eventId: string) => void;
  onViewIncident: (incidentId: string) => void;
  onClearBuffer: () => void;
  isStreaming: boolean;
  onToggleStreaming: () => void;
  metrics: StreamMetrics;
  searchFilter: string;
  theme?: ThemeMode;
  backendStatus?: 'checking' | 'connected' | 'unavailable';
  dashboardMetrics?: {
    activeIncidents: number;
    totalAlerts: number;
    incidentSeverity?: Record<string, number>;
    incidentStatus?: Record<string, number>;
  } | null;
}

export const LiveEventStream: React.FC<LiveEventStreamProps> = ({
  events,
  selectedEventId,
  onSelectEvent,
  onBlockIp,
  onQuarantineHost,
  onCorrelateIncident,
  onViewIncident,
  onClearBuffer,
  isStreaming,
  onToggleStreaming,
  metrics,
  searchFilter,
  theme = 'dark',
  backendStatus = 'checking',
  dashboardMetrics = null,
}) => {
  const [autoScroll, setAutoScroll] = useState(true);
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'ALL'>('ALL');
  const [typeFilter, setTypeFilter] = useState<string>('All Types');
  const [ipCidrFilter, setIpCidrFilter] = useState('');
  const [regexFilter, setRegexFilter] = useState('');
  const [isDrawerPinned, setIsDrawerPinned] = useState(true);
  const [isDrawerOpen, setIsDrawerOpen] = useState(true);
  const [quickActionMenuId, setQuickActionMenuId] = useState<string | null>(null);

  const isLight = theme === 'light';
  const tableContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll effect when new events arrive
  useEffect(() => {
    if (autoScroll && tableContainerRef.current) {
      tableContainerRef.current.scrollTop = 0;
    }
  }, [events, autoScroll]);

  // Counts for severities
  const critCount = useMemo(
    () => events.filter((e) => e.severity === 'CRITICAL').length,
    [events]
  );
  const highCount = useMemo(
    () => events.filter((e) => e.severity === 'HIGH').length,
    [events]
  );
  const medCount = useMemo(
    () => events.filter((e) => e.severity === 'MEDIUM').length,
    [events]
  );
  const lowCount = useMemo(
    () => events.filter((e) => e.severity === 'LOW').length,
    [events]
  );

  // Filtered Events
  const filteredEvents = useMemo(() => {
    return events.filter((event) => {
      // Source filter
      if (sourceFilter !== 'ALL' && event.source !== sourceFilter) {
        if (sourceFilter === 'Okta (Active)' && event.source !== 'Okta') {
          // soft match
        } else if (sourceFilter !== 'Okta (Active)') {
          return false;
        }
      }

      // Severity filter
      if (severityFilter !== 'ALL' && event.severity !== severityFilter) {
        return false;
      }

      // Type filter
      if (typeFilter !== 'All Types') {
        if (typeFilter === 'Auth / Identity Bypass') {
          // Keep display consistent with sample
        }
      }

      // IP / CIDR search
      if (ipCidrFilter.trim()) {
        const query = ipCidrFilter.trim().toLowerCase();
        const ipMatches =
          event.sourceIp.toLowerCase().includes(query) ||
          (event.sourceHost && event.sourceHost.toLowerCase().includes(query)) ||
          event.destination.toLowerCase().includes(query);
        if (!ipMatches) return false;
      }

      // Regex search
      if (regexFilter.trim()) {
        try {
          const reg = new RegExp(regexFilter.replace(/^\/|\/[a-z]*$/g, ''), 'i');
          const testString = `${event.id} ${event.eventType} ${event.principal} ${event.sourceIp} ${event.destination}`;
          if (!reg.test(testString)) return false;
        } catch {
          // Ignore regex errors
        }
      }

      // Global search filter
      if (searchFilter.trim()) {
        const q = searchFilter.trim().toLowerCase();
        const matches =
          event.id.toLowerCase().includes(q) ||
          event.principal.toLowerCase().includes(q) ||
          event.eventType.toLowerCase().includes(q) ||
          event.sourceIp.toLowerCase().includes(q) ||
          (event.sourceHost && event.sourceHost.toLowerCase().includes(q)) ||
          event.destination.toLowerCase().includes(q) ||
          (event.correlatedIncident && event.correlatedIncident.toLowerCase().includes(q));
        if (!matches) return false;
      }

      return true;
    });
  }, [events, sourceFilter, severityFilter, typeFilter, ipCidrFilter, regexFilter, searchFilter]);

  const selectedEvent = useMemo(() => {
    return (
      events.find((e) => e.id === selectedEventId) ||
      filteredEvents[0] ||
      events[0] ||
      null
    );
  }, [events, selectedEventId, filteredEvents]);

  const handleExport = () => {
    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(filteredEvents, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `hawkeye_events_export_${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div
      id="live-events-screen"
      className={`fixed top-14 left-60 bottom-7 right-0 overflow-hidden flex flex-col select-none transition-colors duration-200 ${
        isLight ? 'bg-[#f4f5f8] text-[#0f172a]' : 'bg-[#000000] text-[#f3f0f3]'
      }`}
    >
      {/* SUB-HEADER SECTION: Title, Description & HIGHLIGHTED STREAM CONTROLS */}
      <div className={`relative px-5 py-2.5 border-b flex flex-wrap items-center justify-between gap-4 shrink-0 overflow-hidden shadow-md transition-colors duration-200 ${
        isLight
          ? 'bg-[#ffffff] border-[#e2e8f0]'
          : 'dynamic-red-black-bg border-[#7f1d1d]/60'
      }`}>
        {/* Ambient Grid overlay */}
        <div className={`absolute inset-0 pointer-events-none opacity-30 ${isLight ? 'cyber-grid-gold-overlay' : 'cyber-grid-overlay'}`} />

        <div className="relative z-10">
          <div className="flex items-center gap-2.5">
            <h1 className={`font-['Space_Grotesk'] text-[20px] font-bold tracking-tight flex items-center gap-2 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              <span className="inline-block w-2 h-2 rounded-full bg-[#ef4444] pulse-beacon shadow-[0_0_8px_#ef4444]" />
              Live Event Stream
            </h1>
            <span className={`px-2 py-0.5 font-['JetBrains_Mono'] text-[9.5px] font-bold tracking-wider border ${
              isLight
                ? 'bg-[#fee2e2] border-[#fca5a5] text-[#b91c1c]'
                : 'bg-[#7f1d1d]/60 border-[#dc2626] text-[#fee2e2] shadow-[0_0_8px_rgba(239,68,68,0.25)]'
            }`}>
              LIVE INGESTION
            </span>
          </div>
          <p className={`font-['Geist'] text-[12px] mt-0.5 ${isLight ? 'text-[#64748b]' : 'text-[#e5e5e5]/80'}`}>
            Continuous telemetry ingestion across cloud, endpoint, identity, and network sensors.
          </p>
        </div>

        {/* HIGHLIGHTED STREAM CONTROLS */}
        <div className="relative z-10 flex items-center gap-2.5">
          {/* Highlighted Button 1: Auto-Scroll */}
          <button
            type="button"
            id="toggle-autoscroll-btn"
            onClick={() => setAutoScroll(!autoScroll)}
            className={`h-7 px-3 font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-all duration-200 border ${
              autoScroll
                ? isLight
                  ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c]'
                  : 'bg-[#000000] border-[#ef4444] text-[#ef4444] shadow-[0_0_10px_rgba(239,68,68,0.3)]'
                : isLight
                  ? 'bg-[#ffffff] border-[#cbd5e1] text-[#64748b] hover:border-[#dc2626] hover:text-[#0f172a]'
                  : 'bg-[#000000] border-[#7f1d1d]/60 text-[#9ca3af] hover:border-[#ef4444] hover:text-[#ffffff]'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                autoScroll ? 'bg-[#ef4444] pulse-beacon shadow-[0_0_6px_#ef4444]' : 'bg-[#6b7280]'
              }`}
            />
            {autoScroll ? 'Auto-scroll: ON' : 'Auto-scroll: OFF'}
          </button>

          {/* Highlighted Button 2: Pause / Resume */}
          <button
            type="button"
            id="toggle-pause-stream-btn"
            onClick={onToggleStreaming}
            className={`h-7 px-2.5 font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-all duration-200 border ${
              isStreaming
                ? isLight
                  ? 'bg-[#ffffff] border-[#cbd5e1] hover:border-[#dc2626] text-[#b91c1c] hover:bg-[#fee2e2]'
                  : 'bg-[#000000] border-[#7f1d1d] hover:border-[#ef4444] text-[#ef4444] hover:bg-[#ef4444]/15 shadow-[0_0_8px_rgba(239,68,68,0.2)]'
                : isLight
                  ? 'bg-[#fee2e2] border-[#dc2626] text-[#991b1b]'
                  : 'bg-[#7f1d1d]/50 border-[#ef4444] text-[#ffffff] shadow-[0_0_12px_rgba(239,68,68,0.4)]'
            }`}
          >
            <span className="material-symbols-outlined text-[14px]">
              {isStreaming ? 'pause' : 'play_arrow'}
            </span>
            {isStreaming ? 'Pause' : 'Resume'}
          </button>

          {/* Highlighted Button 3: Export JSON */}
          <button
            type="button"
            id="btn-export-pcap-json"
            onClick={handleExport}
            className={`h-7 px-2.5 border font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-all duration-200 ${
              isLight
                ? 'bg-[#ffffff] border-[#cbd5e1] hover:border-[#dc2626] hover:bg-[#fee2e2] text-[#b91c1c]'
                : 'bg-[#000000] border-[#7f1d1d]/70 hover:border-[#ef4444] hover:bg-[#dc2626]/20 text-[#ff8080] hover:text-[#ffffff] shadow-[0_0_8px_rgba(220,38,38,0.2)]'
            }`}
          >
            <span className="material-symbols-outlined text-[14px] text-[#ef4444]">download</span>
            Export JSON
          </button>

          {/* Highlighted Button 4: Clear Buffer */}
          <button
            type="button"
            id="btn-clear-buffer"
            onClick={onClearBuffer}
            className={`h-7 px-2.5 border font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-all duration-200 ${
              isLight
                ? 'bg-[#ffffff] border-[#cbd5e1] text-[#b91c1c] hover:bg-[#fee2e2] hover:border-[#dc2626]'
                : 'bg-[#000000] border-[#7f1d1d]/70 text-[#ff8080] hover:text-[#ffffff] hover:bg-[#7f1d1d] hover:border-[#ef4444]'
            }`}
          >
            <span className="material-symbols-outlined text-[14px]">delete_sweep</span>
            Clear
          </button>

          <div className={`h-5 w-px mx-0.5 ${isLight ? 'bg-[#e2e8f0]' : 'bg-[#7f1d1d]/50'}`} />

          {/* Highlighted Button 5: Drawer Toggle */}
          <button
            type="button"
            id="btn-toggle-drawer"
            onClick={() => setIsDrawerOpen(!isDrawerOpen)}
            className={`h-7 px-2.5 font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-all duration-200 border ${
              isDrawerOpen
                ? isLight
                  ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c]'
                  : 'bg-[#000000] border-[#ef4444] text-[#ef4444] shadow-[0_0_10px_rgba(239,68,68,0.3)]'
                : isLight
                  ? 'bg-[#ffffff] border-[#cbd5e1] text-[#475569] hover:border-[#dc2626] hover:text-[#0f172a]'
                  : 'bg-[#000000] border-[#7f1d1d]/60 text-[#d1d5db] hover:border-[#ef4444] hover:text-[#ffffff]'
            }`}
            title="Toggle Right Context Inspector Panel"
          >
            <span className="material-symbols-outlined text-[14px]">
              {isDrawerOpen ? 'dock_to_right' : 'vertical_split'}
            </span>
            {isDrawerOpen ? 'Inspector Open' : 'Open Inspector'}
          </button>
        </div>
      </div>

      {/* LIVE METRICS BAR (4 Columns) */}
      <div className={`grid grid-cols-4 border-b shrink-0 transition-colors duration-200 divide-x ${
        isLight
          ? 'bg-[#ffffff] border-[#e2e8f0] divide-[#e2e8f0]'
          : 'bg-[#000000] border-[#7f1d1d]/50 divide-[#22090c]'
      }`}>
        <div className="px-5 py-2 flex items-center justify-between">
          <div>
            <div className={`font-['JetBrains_Mono'] text-[9.5px] tracking-wider uppercase font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
              Ingestion Rate
            </div>
            <div className={`font-['JetBrains_Mono'] text-[14px] font-semibold flex items-baseline gap-1.5 mt-0.5 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              {backendStatus === 'connected' ? (
                metrics.ingestionRate != null ? (
                  <span className="text-[11px] opacity-90 font-semibold">{metrics.ingestionRate.toLocaleString()} eps</span>
                ) : (
                  <span className="text-[11px] opacity-75 font-normal">METRIC UNAVAILABLE</span>
                )
              ) : (
                <>
                  {metrics.ingestionRate?.toLocaleString() ?? 'N/A'}{' '}
                  <span className={`text-[10px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                    eps
                  </span>
                  <span className="text-[10px] font-mono font-bold text-[#ef4444]">
                    {metrics.peakRateChange}
                  </span>
                </>
              )}
            </div>
          </div>
          <div className={`w-8 h-8 rounded flex items-center justify-center border shrink-0 ${
            isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]'
          }`}>
            <span className="material-symbols-outlined text-[17px] text-[#ef4444]">
              speed
            </span>
          </div>
        </div>

        <div className="px-5 py-2 flex items-center justify-between">
          <div>
            <div className={`font-['JetBrains_Mono'] text-[9.5px] tracking-wider uppercase font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
              Total Events Today
            </div>
            <div className={`font-['JetBrains_Mono'] text-[14px] font-semibold flex items-baseline gap-1.5 mt-0.5 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              {backendStatus === 'connected' ? (
                dashboardMetrics?.totalAlerts !== undefined ? (
                  <span>
                    {dashboardMetrics.totalAlerts}{' '}
                    <span className="text-[10px] font-bold text-[#10b981]">live alerts</span>
                  </span>
                ) : (
                  <span className="text-[11px] opacity-75 font-normal">METRIC UNAVAILABLE</span>
                )
              ) : (
                <>
                  {metrics.totalEventsToday ?? 'N/A'}{' '}
                  <span className="text-[10px] font-bold text-[#ef4444]">
                    synced
                  </span>
                </>
              )}
            </div>
          </div>
          <div className={`w-8 h-8 rounded flex items-center justify-center border shrink-0 ${
            isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]'
          }`}>
            <span className="material-symbols-outlined text-[17px] text-[#ef4444]">
              database
            </span>
          </div>
        </div>

        <div className="px-5 py-2 flex items-center justify-between">
          <div>
            <div className={`font-['JetBrains_Mono'] text-[9.5px] tracking-wider uppercase font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
              Active Log Sources
            </div>
            <div className={`font-['JetBrains_Mono'] text-[14px] font-semibold flex items-baseline gap-1.5 mt-0.5 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              {backendStatus === 'connected' ? (
                <span className="text-[11px] opacity-75 font-normal">METRIC UNAVAILABLE</span>
              ) : (
                <>
                  {metrics.activeLogSources ?? 'N/A'} / {metrics.totalLogSources ?? 'N/A'}{' '}
                  <span className="text-[10px] font-semibold text-[#ef4444]">
                    availability unavailable
                  </span>
                </>
              )}
            </div>
          </div>
          <div className={`w-8 h-8 rounded flex items-center justify-center border shrink-0 ${
            isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]'
          }`}>
            <span className="material-symbols-outlined text-[17px] text-[#ef4444]">
              hub
            </span>
          </div>
        </div>

        <div className="px-5 py-2 flex items-center justify-between">
          <div>
            <div className={`font-['JetBrains_Mono'] text-[9.5px] tracking-wider uppercase font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
              Pipeline Drop Rate
            </div>
            <div className={`font-['JetBrains_Mono'] text-[14px] font-semibold flex items-baseline gap-1.5 mt-0.5 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              {backendStatus === 'connected' ? (
                <span className="text-[11px] opacity-75 font-normal">METRIC UNAVAILABLE</span>
              ) : (
                <>
                  {metrics.pipelineDropRate}{' '}
                  <span className={`text-[10px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                    {metrics.errorPerSec} err/sec
                  </span>
                </>
              )}
            </div>
          </div>
          <div className={`w-8 h-8 rounded flex items-center justify-center border shrink-0 ${
            isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]'
          }`}>
            <span className="material-symbols-outlined text-[17px] text-[#ef4444]">
              check_circle
            </span>
          </div>
        </div>
      </div>

      {/* MULTI-DIMENSIONAL FILTER BAR */}
      <div className={`px-5 py-2 border-b flex flex-wrap items-center gap-3 shrink-0 transition-colors duration-200 ${
        isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]/40'
      }`}>
        {/* Source Filter Chips */}
        <div className="flex items-center gap-1.5">
          <span className={`font-['JetBrains_Mono'] text-[10px] mr-1 uppercase tracking-wider font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
            Source:
          </span>
          {[
            'ALL',
            'CrowdStrike',
            'Palo Alto FW',
            'Okta (Active)',
            'AWS CloudTrail',
            'Zeek',
            'Suricata',
          ].map((src) => {
            const isSelected =
              sourceFilter === src ||
              (src === 'Okta (Active)' && sourceFilter === 'Okta') ||
              (src === 'Okta (Active)' && sourceFilter === 'Okta (Active)');
            return (
              <button
                key={src}
                type="button"
                onClick={() => {
                  if (src === 'Okta (Active)') {
                    setSourceFilter(sourceFilter === 'Okta' ? 'ALL' : 'Okta');
                  } else {
                    setSourceFilter(sourceFilter === src ? 'ALL' : src);
                  }
                }}
                className={`px-2 py-0.5 font-['JetBrains_Mono'] text-[10px] tracking-wide transition-colors ${
                  isSelected
                    ? isLight
                      ? 'bg-[#fee2e2] border border-[#dc2626] text-[#991b1b] font-bold'
                      : 'bg-[#7f1d1d] border border-[#ef4444] text-[#ffffff] font-bold shadow-[0_0_8px_rgba(239,68,68,0.35)]'
                    : isLight
                      ? 'bg-[#ffffff] border border-[#cbd5e1] text-[#64748b] hover:text-[#0f172a] hover:border-[#94a3b8]'
                      : 'bg-[#000000] border border-[#450a0a] text-[#9ca3af] hover:text-[#ffffff] hover:border-[#ef4444]'
                }`}
              >
                {src}
              </button>
            );
          })}
        </div>

        <div className={`h-4 w-px ${isLight ? 'bg-[#e2e8f0]' : 'bg-[#7f1d1d]/50'}`} />

        {/* Severity Filter */}
        <div className="flex items-center gap-1.5">
          <span className={`font-['JetBrains_Mono'] text-[10px] mr-1 uppercase tracking-wider font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
            Sev:
          </span>
          <button
            type="button"
            onClick={() => setSeverityFilter(severityFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}
            className={`px-2 py-0.5 font-['JetBrains_Mono'] text-[10px] tracking-wide font-bold ${
              severityFilter === 'CRITICAL'
                ? isLight
                  ? 'bg-[#fee2e2] border border-[#dc2626] text-[#991b1b]'
                  : 'bg-[#7f1d1d] border border-[#ef4444] text-[#ffffff] shadow-[0_0_8px_rgba(239,68,68,0.4)]'
                : isLight
                  ? 'bg-[#ffffff] border border-[#cbd5e1] text-[#dc2626] hover:bg-[#fee2e2]'
                  : 'bg-[#000000] border border-[#7f1d1d]/60 text-[#ff8080] hover:bg-[#7f1d1d]/40'
            }`}
          >
            CRIT ({critCount})
          </button>
          <button
            type="button"
            onClick={() => setSeverityFilter(severityFilter === 'HIGH' ? 'ALL' : 'HIGH')}
            className={`px-2 py-0.5 font-['JetBrains_Mono'] text-[10px] tracking-wide font-bold ${
              severityFilter === 'HIGH'
                ? isLight
                  ? 'bg-[#fee2e2] border border-[#dc2626] text-[#b91c1c]'
                  : 'bg-[#450a0a] border border-[#dc2626] text-[#ffffff] shadow-[0_0_8px_rgba(220,38,38,0.3)]'
                : isLight
                  ? 'bg-[#ffffff] border border-[#cbd5e1] text-[#b91c1c] hover:bg-[#fef2f2]'
                  : 'bg-[#000000] border border-[#7f1d1d]/50 text-[#ff8080] hover:bg-[#450a0a]/50'
            }`}
          >
            HIGH ({highCount})
          </button>
          <button
            type="button"
            onClick={() => setSeverityFilter(severityFilter === 'MEDIUM' ? 'ALL' : 'MEDIUM')}
            className={`px-2 py-0.5 font-['JetBrains_Mono'] text-[10px] tracking-wide ${
              severityFilter === 'MEDIUM'
                ? isLight
                  ? 'bg-[#fef3c7] border border-[#f59e0b] text-[#b45309] font-semibold'
                  : 'bg-[#18090b] border border-[#ef4444]/60 text-[#ff8080] font-semibold'
                : isLight
                  ? 'bg-[#ffffff] border border-[#cbd5e1] text-[#64748b] hover:text-[#b45309]'
                  : 'bg-[#000000] border border-[#4a1216] text-[#9ca3af] hover:text-[#ff8080]'
            }`}
          >
            MED ({medCount})
          </button>
          <button
            type="button"
            onClick={() => setSeverityFilter(severityFilter === 'LOW' ? 'ALL' : 'LOW')}
            className={`px-2 py-0.5 font-['JetBrains_Mono'] text-[10px] tracking-wide ${
              severityFilter === 'LOW'
                ? isLight
                  ? 'bg-[#f1f5f9] border border-[#94a3b8] text-[#334155] font-semibold'
                  : 'bg-[#151515] border border-[#555] text-[#ffffff] font-semibold'
                : isLight
                  ? 'bg-[#ffffff] border border-[#cbd5e1] text-[#64748b] hover:text-[#0f172a]'
                  : 'bg-[#000000] border border-[#333] text-[#9ca3af] hover:text-[#ffffff]'
            }`}
          >
            LOW ({lowCount})
          </button>
        </div>

        <div className={`h-4 w-px ${isLight ? 'bg-[#e2e8f0]' : 'bg-[#7f1d1d]/50'}`} />

        {/* Event Type Dropdown */}
        <div className="flex items-center gap-1.5">
          <span className={`font-['JetBrains_Mono'] text-[10px] uppercase tracking-wider font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
            Type:
          </span>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className={`h-6 px-2 font-['JetBrains_Mono'] text-[11px] focus:outline-none border ${
              isLight
                ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a] focus:border-[#dc2626]'
                : 'bg-[#000000] border border-[#450a0a] text-[#ffffff] focus:border-[#ef4444]'
            }`}
          >
            <option value="All Types">All Types</option>
            <option value="Auth / Identity Bypass">Auth / Identity Bypass</option>
            <option value="Process Injected">Process Injected</option>
            <option value="DNS Exfil">DNS Exfil</option>
            <option value="IAM Escalation">IAM Escalation</option>
          </select>
        </div>

        {/* IP/CIDR & Regex inputs */}
        <div className="ml-auto flex items-center gap-2">
          <input
            type="text"
            value={ipCidrFilter}
            onChange={(e) => setIpCidrFilter(e.target.value)}
            placeholder="IP / CIDR filter"
            className={`h-6 px-2 w-36 font-['JetBrains_Mono'] text-[11px] focus:outline-none border ${
              isLight
                ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a] placeholder:text-[#94a3b8] focus:border-[#dc2626]'
                : 'bg-[#000000] border border-[#450a0a] text-[#ffffff] placeholder:text-[#6b7280] focus:border-[#ef4444]'
            }`}
          />
          <input
            type="text"
            value={regexFilter}
            onChange={(e) => setRegexFilter(e.target.value)}
            placeholder="/regex/i"
            className={`h-6 px-2 w-24 font-['JetBrains_Mono'] text-[11px] focus:outline-none border ${
              isLight
                ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a] placeholder:text-[#94a3b8] focus:border-[#dc2626]'
                : 'bg-[#000000] border border-[#450a0a] text-[#ffffff] placeholder:text-[#6b7280] focus:border-[#ef4444]'
            }`}
          />
        </div>
      </div>

      {/* MAIN TELEMETRY STREAM & CONTEXT DRAWER */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Stream Table Wrapper */}
        <div
          ref={tableContainerRef}
          className={`flex-1 overflow-y-auto custom-scrollbar transition-colors duration-200 ${
            isLight ? 'bg-[#ffffff]' : 'bg-[#000000]'
          }`}
        >
          <table className="w-full text-left border-collapse">
            <thead className={`sticky top-0 z-10 border-b font-['JetBrains_Mono'] text-[10px] tracking-wider transition-colors duration-200 ${
              isLight
                ? 'bg-[#f8fafc] border-[#e2e8f0] text-[#b91c1c]'
                : 'bg-[#000000] border-[#7f1d1d] text-[#ef4444]'
            }`}>
              <tr>
                <th className="py-2.5 px-3 w-8"></th>
                <th className="py-2.5 px-4 w-32">TIMESTAMP</th>
                <th className="py-2.5 px-3 w-24">SEVERITY</th>
                <th className="py-2.5 px-3 w-32">SOURCE</th>
                <th className="py-2.5 px-3 w-48">EVENT TYPE</th>
                <th className="py-2.5 px-3 w-44">PRINCIPAL</th>
                <th className="py-2.5 px-3 w-44">SOURCE IP / HOST</th>
                <th className="py-2.5 px-3">DESTINATION</th>
                <th className="py-2.5 px-3 w-32">CORRELATED</th>
                <th className="py-2.5 px-3 text-right w-16"></th>
              </tr>
            </thead>
            <tbody className={`font-['JetBrains_Mono'] text-[12.5px] divide-y ${
              isLight ? 'divide-[#f1f5f9]' : 'divide-[#1c070a]'
            }`}>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td
                    colSpan={10}
                    className={`py-16 text-center ${isLight ? 'text-[#64748b]' : 'text-[#ab8986]'}`}
                  >
                    <div
                      className={`font-['Space_Grotesk'] text-[16px] ${
                        isLight ? 'text-[#0f172a]' : 'text-[#e4beba]'
                      }`}
                    >
                      No events match current filters
                    </div>
                    <div className="text-[11px] mt-1 font-['JetBrains_Mono']">
                      Reset filters or use the Threat Simulator to inject active events.
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setSourceFilter('ALL');
                        setSeverityFilter('ALL');
                        setTypeFilter('All Types');
                        setIpCidrFilter('');
                        setRegexFilter('');
                      }}
                      className={`mt-3 px-3.5 py-1 border font-['JetBrains_Mono'] text-[11px] ${
                        isLight
                          ? 'bg-[#fee2e2] border-[#dc2626] text-[#991b1b]'
                          : 'bg-[#201f22] border-[#ff5451] text-[#ffb3ad]'
                      }`}
                    >
                      Reset All Filters
                    </button>
                  </td>
                </tr>
              ) : (
                filteredEvents.map((event) => {
                  const isSelected = selectedEvent?.id === event.id;
                  const isCrit = event.severity === 'CRITICAL';
                  const isHigh = event.severity === 'HIGH';

                  const rowClass = isSelected
                    ? isLight
                      ? 'bg-[#fee2e2]/60 border-l-2 border-[#dc2626] cursor-pointer'
                      : 'bg-[#1a0407] border-l-2 border-[#ef4444] shadow-[inset_0_0_15px_rgba(220,38,38,0.25)] cursor-pointer'
                    : isCrit
                    ? isLight
                      ? 'bg-[#fef2f2] hover:bg-[#fee2e2] cursor-pointer'
                      : 'bg-[#0e0204]/90 hover:bg-[#1a0508] cursor-pointer transition-colors'
                    : isHigh
                    ? isLight
                      ? 'bg-[#fff5f5] hover:bg-[#fee2e2]/70 cursor-pointer'
                      : 'bg-[#0a0203]/70 hover:bg-[#150406] cursor-pointer transition-colors'
                    : isLight
                      ? 'bg-[#ffffff] hover:bg-[#f8fafc] cursor-pointer transition-colors'
                      : 'bg-[#000000] hover:bg-[#0c0507] cursor-pointer transition-colors';

                  return (
                    <tr
                      key={event.id}
                      onClick={() => {
                        onSelectEvent(event.id);
                        if (!isDrawerOpen) setIsDrawerOpen(true);
                      }}
                      className={rowClass}
                    >
                      {/* Status indicator pip */}
                      <td className="py-3 px-3">
                        {isCrit ? (
                          <span className="w-2 h-2 rounded-full bg-[#ef4444] block pulse-beacon shadow-[0_0_6px_#ef4444]" />
                        ) : isHigh ? (
                          <span className="w-2 h-2 rounded-full bg-[#dc2626] block shadow-[0_0_6px_#dc2626]" />
                        ) : (
                          <span className={`w-1.5 h-1.5 rounded-full block ${isLight ? 'bg-[#94a3b8]' : 'bg-[#555555]'}`} />
                        )}
                      </td>

                      {/* Timestamp */}
                      <td
                        className={`py-3 px-4 font-['JetBrains_Mono'] text-[11.5px] whitespace-nowrap ${
                          isCrit
                            ? isLight ? 'text-[#b91c1c] font-bold' : 'text-[#ff4d4d] font-bold'
                            : isHigh
                            ? isLight ? 'text-[#dc2626]' : 'text-[#f87171]'
                            : isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
                        }`}
                      >
                        {event.timestamp}
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-3">
                        <span
                          className={`font-['JetBrains_Mono'] text-[9.5px] px-2 py-0.5 border font-semibold inline-block ${
                            isCrit
                              ? isLight
                                ? 'bg-[#fee2e2] border-[#dc2626] text-[#991b1b]'
                                : 'bg-[#7f1d1d]/90 border-[#ef4444] text-[#ffffff] shadow-[0_0_6px_rgba(239,68,68,0.3)]'
                              : isHigh
                              ? isLight
                                ? 'bg-[#fef2f2] border-[#fca5a5] text-[#b91c1c]'
                                : 'bg-[#450a0a] border-[#dc2626] text-[#fca5a5] shadow-[0_0_6px_rgba(220,38,38,0.25)]'
                              : event.severity === 'MEDIUM'
                              ? isLight
                                ? 'bg-[#fef3c7] border-[#fcd34d] text-[#b45309]'
                                : 'bg-[#160608] border-[#ef4444]/60 text-[#ff8080]'
                              : isLight
                                ? 'bg-[#f1f5f9] border-[#cbd5e1] text-[#475569]'
                                : 'bg-[#000000] border-[#444444] text-[#9ca3af]'
                          }`}
                        >
                          {event.severity}
                        </span>
                      </td>

                      {/* Source */}
                      <td className={`py-3 px-3 font-['JetBrains_Mono'] text-[12px] whitespace-nowrap ${isLight ? 'text-[#334155]' : 'text-[#e5e5e5]'}`}>
                        {event.source}
                      </td>

                      {/* Event Type */}
                      <td className={`py-3 px-3 font-['Space_Grotesk'] text-[13px] font-medium ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                        <span className="truncate block max-w-xs">{event.eventType}</span>
                      </td>

                      {/* Principal / User */}
                      <td className={`py-3 px-3 font-['JetBrains_Mono'] text-[11.5px] truncate max-w-xs ${isLight ? 'text-[#b91c1c]' : 'text-[#ff8080]'}`}>
                        {event.principal}
                      </td>

                      {/* Source IP / Host stacked */}
                      <td className="py-3 px-3 font-['JetBrains_Mono'] text-[11.5px]">
                        <div className={`font-semibold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                          {event.sourceIp}
                        </div>
                        {event.sourceHost && (
                          <div className={`text-[10px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                            {event.sourceHost}
                          </div>
                        )}
                      </td>

                      {/* Destination / Target */}
                      <td className={`py-3 px-3 font-['JetBrains_Mono'] text-[11.5px] truncate max-w-xs ${isLight ? 'text-[#475569]' : 'text-[#d1d5db]'}`}>
                        {event.destination}
                      </td>

                      {/* Correlated Incident */}
                      <td className="py-3 px-3 whitespace-nowrap font-['JetBrains_Mono'] text-[10.5px]">
                        {event.correlatedIncident ? (
                          <span
                            onClick={(e) => {
                              e.stopPropagation();
                              onViewIncident(event.correlatedIncident!);
                            }}
                            className={`hover:underline cursor-pointer font-bold inline-flex items-center gap-1 ${
                              isLight ? 'text-[#b91c1c] hover:text-[#991b1b]' : 'text-[#ff8080] hover:text-[#ffffff]'
                            }`}
                          >
                            <span>{event.correlatedIncident}</span>
                            {event.riskScore && (
                              <span className={`px-1 py-0.2 rounded-xs font-normal text-[9px] border ${
                                isLight
                                  ? 'bg-[#fee2e2] text-[#991b1b] border-[#dc2626]'
                                  : 'bg-[#7f1d1d] text-[#ffffff] border-[#ef4444]'
                              }`}>
                                {event.riskScore}
                              </span>
                            )}
                          </span>
                        ) : (
                          <span className={isLight ? 'text-[#94a3b8]' : 'text-[#6b7280]'}>
                            UNLINKED
                          </span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-3 text-right whitespace-nowrap relative">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setQuickActionMenuId(
                              quickActionMenuId === event.id ? null : event.id
                            );
                          }}
                          className={`w-6 h-6 inline-flex items-center justify-center rounded transition-colors ${
                            isLight
                              ? 'text-[#64748b] hover:text-[#0f172a] hover:bg-[#fee2e2]'
                              : 'text-[#9ca3af] hover:text-[#ffffff] hover:bg-[#1a080a]'
                          }`}
                          title="Quick Actions"
                        >
                          <span className="material-symbols-outlined text-[15px]">more_vert</span>
                        </button>

                        {/* Quick action popup */}
                        {quickActionMenuId === event.id && (
                          <div
                            onClick={(e) => e.stopPropagation()}
                            className={`absolute right-3 top-8 z-30 w-44 shadow-2xl py-1 text-left font-['JetBrains_Mono'] text-[11px] border ${
                              isLight
                                ? 'bg-[#ffffff] border-[#e2e8f0] text-[#0f172a]'
                                : 'bg-[#000000] border-[#7f1d1d] text-[#ffffff]'
                            }`}
                          >
                            <button
                              type="button"
                              onClick={() => {
                                onBlockIp(event.sourceIp);
                                setQuickActionMenuId(null);
                              }}
                              className={`w-full px-3 py-1.5 flex items-center gap-2 transition-colors ${
                                isLight
                                  ? 'hover:bg-[#fee2e2] text-[#b91c1c]'
                                  : 'hover:bg-[#7f1d1d] text-[#ff8080] hover:text-[#ffffff]'
                              }`}
                            >
                              <span className="material-symbols-outlined text-[13px]">block</span>
                              Block Source IP
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                onQuarantineHost(event.sourceHost || event.sourceIp);
                                setQuickActionMenuId(null);
                              }}
                              className={`w-full px-3 py-1.5 flex items-center gap-2 transition-colors ${
                                isLight
                                  ? 'hover:bg-[#fee2e2] text-[#b91c1c]'
                                  : 'hover:bg-[#7f1d1d] text-[#ff8080] hover:text-[#ffffff]'
                              }`}
                            >
                              <span className="material-symbols-outlined text-[13px]">cell_wifi</span>
                              Isolate Host
                            </button>
                            <button
                              type="button"
                              onClick={() => {
                                onCorrelateIncident(event.id);
                                setQuickActionMenuId(null);
                              }}
                              className={`w-full px-3 py-1.5 flex items-center gap-2 transition-colors ${
                                isLight
                                  ? 'hover:bg-[#f1f5f9] text-[#0f172a]'
                                  : 'hover:bg-[#1a080a] hover:text-[#ffffff] text-[#e5e5e5]'
                              }`}
                            >
                              <span className="material-symbols-outlined text-[13px]">merge_type</span>
                              Correlate to Case
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* SLIDE-OVER EVENT CONTEXT DRAWER */}
        {isDrawerOpen && (
          <EventContextDrawer
            event={selectedEvent}
            onClose={() => setIsDrawerOpen(false)}
            onViewIncident={onViewIncident}
            onBlockIp={onBlockIp}
            onQuarantineHost={onQuarantineHost}
            onCorrelateIncident={onCorrelateIncident}
            isPinned={isDrawerPinned}
            onTogglePin={() => setIsDrawerPinned(!isDrawerPinned)}
            theme={theme}
          />
        )}
      </div>
    </div>
  );
};
