import React, { useState } from 'react';
import { IncidentRecord, StreamMetrics, ThemeMode } from '../types';
import { AutonomousVectorRadar } from './AutonomousVectorRadar';

interface OverviewViewProps {
  metrics: StreamMetrics;
  incidents: IncidentRecord[];
  events?: import('../types').SecurityEvent[];
  onSelectIncident: (id: string) => void;
  onNavigateToLive: () => void;
  theme?: ThemeMode;
  backendStatus?: 'checking' | 'connected' | 'unavailable';
  dashboardMetrics?: {
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
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  metrics,
  incidents,
  events = [],
  onSelectIncident,
  onNavigateToLive,
  theme = 'dark',
  backendStatus = 'checking',
  dashboardMetrics = null,
}) => {
  const isLight = theme === 'light';

  const [isRadarModalOpen, setIsRadarModalOpen] = useState(false);

  const killChainNames = ['Reconnaissance', 'Initial Access', 'Execution', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Command & Control', 'Exfiltration'];
  const killChainStages = killChainNames.map((name) => ({
    name,
    count: incidents.reduce((total, incident) =>
      total + (incident.timelineEvents || []).filter((event) =>
        event.tactic?.toLowerCase() === name.toLowerCase()
      ).length, 0),
    active: incidents.length > 0,
    critical: name === 'Command & Control' || name === 'Exfiltration',
  }));

  // Backend-derived counts only: incidents list is hydrated from /api/incidents,
  // affected assets from the incident records returned by the backend.
  const activeIncidents = incidents.filter(
    (i) => !['CLOSED', 'MITIGATED'].includes(String((i as { status?: string }).status ?? '').toUpperCase())
  );
  const criticalCount = activeIncidents.filter(
    (i) => String((i as { severity?: string }).severity ?? '').toUpperCase() === 'CRITICAL'
  ).length;
  const containedCount = incidents.reduce(
    (n, i) =>
      n +
      (((i as { affectedAssets?: Array<{ status?: string }> }).affectedAssets || []).filter((a) =>
        ['ISOLATED', 'CONTAINED'].includes(String(a.status ?? '').toUpperCase())
      ).length),
    0
  );

  return (
    <div
      id="overview-screen"
      className={`fixed top-14 left-60 bottom-7 right-0 overflow-y-auto custom-scrollbar p-4 space-y-4 select-none transition-colors duration-200 ${
        isLight
          ? 'bg-[#f4f5f8] text-[#0f172a]'
          : 'bg-[#000000] text-[#e5e1e5]'
      }`}
    >
      {/* Overview Header */}
      <div
        className={`flex justify-between items-center pb-2 border-b transition-colors duration-200 ${
          isLight ? 'border-[#e2e8f0]' : 'border-[#7f1d1d]/60'
        }`}
      >
        <div>
          <div className="flex items-center gap-2">
            <h1
              className={`font-['Space_Grotesk'] text-[24px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}
            >
              Autonomous SOC Command Overview
            </h1>
            <span
              className={`px-2 py-0.5 font-['JetBrains_Mono'] text-[10px] font-bold border ${
                isLight
                  ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c]'
                  : 'bg-[#7f1d1d]/60 border-[#ef4444] text-[#fee2e2] shadow-[0_0_8px_rgba(239,68,68,0.3)]'
              }`}
            >
              DEFCON 2 // HIGH ALERT
            </span>
          </div>
          <p
            className={`font-['Geist'] text-[12px] mt-0.5 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}
          >
            Real-time machine-accelerated defense posture, telemetry radar, and autonomous kill-chain progression.
          </p>
        </div>

        <button
          type="button"
          onClick={onNavigateToLive}
          className={`h-8 px-3 border font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-colors ${
            isLight
              ? 'border-[#dc2626] bg-[#fee2e2] text-[#b91c1c] hover:bg-[#dc2626] hover:text-[#ffffff]'
              : 'border-[#ef4444] bg-[#7f1d1d]/40 text-[#ffffff] hover:bg-[#ef4444] shadow-[0_0_10px_rgba(239,68,68,0.25)]'
          }`}
        >
          <span className="material-symbols-outlined text-[15px]">stream</span>
          Switch to Live Telemetry Stream
        </button>
      </div>

      {/* Top 4 Metrics Summary */}
      <div className="grid grid-cols-4 gap-3">
        <div
          className={`p-3 border transition-colors ${
            isLight
              ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm'
              : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
          }`}
        >
          <div
            className={`font-['JetBrains_Mono'] text-[10px] font-semibold ${
              isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/85'
            }`}
          >
            ACTIVE INCIDENTS
          </div>
          <div
            className={`font-['Space_Grotesk'] text-[26px] font-bold mt-1 ${
              isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'
            }`}
          >
            {activeIncidents.length}{' '}
            {criticalCount > 0 && (
              <span
                className={`text-[12px] font-normal font-['JetBrains_Mono'] ${
                  isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
                }`}
              >
                ({criticalCount} Critical)
              </span>
            )}
          </div>
          <div className={`text-[11px] mt-1 ${isLight ? 'text-[#b91c1c]' : 'text-[#ff8080]'}`}>
            Contained entities: {containedCount}
          </div>
        </div>

        <div
          className={`p-3 border transition-colors ${
            isLight
              ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm'
              : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
          }`}
        >
          <div
            className={`font-['JetBrains_Mono'] text-[10px] font-semibold ${
              isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/85'
            }`}
          >
            INGESTION VELOCITY
          </div>
          <div
            className={`font-['Space_Grotesk'] mt-1 ${
              backendStatus === 'connected'
                ? 'text-[15px] font-medium py-1 opacity-75'
                : 'text-[26px] font-bold'
            } ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}
          >
            {backendStatus === 'connected' ? (
              metrics.ingestionRate != null ? (
                <span className="font-['JetBrains_Mono'] text-[12px] opacity-90 font-semibold">
                  {metrics.ingestionRate.toLocaleString()} eps
                </span>
              ) : (
                <span className="font-['JetBrains_Mono'] text-[12px] opacity-75">
                  METRIC UNAVAILABLE
                </span>
              )
            ) : (
              <>
                {metrics.ingestionRate?.toLocaleString() ?? 'N/A'}{' '}
                <span
                  className={`text-[12px] font-normal font-['JetBrains_Mono'] ${
                    isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
                  }`}
                >
                  eps
                </span>
              </>
            )}
          </div>
          <div className={`text-[11px] mt-1 ${isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'}`}>
            {backendStatus === 'connected'
              ? 'Telemetry streaming through Hawkeye backend'
              : 'Telemetry metric unavailable'}
          </div>
        </div>

        <div
          className={`p-3 border transition-colors ${
            isLight
              ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm'
              : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
          }`}
        >
          <div
            className={`font-['JetBrains_Mono'] text-[10px] font-semibold ${
              isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/85'
            }`}
          >
            MEAN TIME TO CONTAIN
          </div>
          <div
            className={`font-['Space_Grotesk'] text-[26px] font-bold mt-1 ${
              isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'
            }`}
          >
            {dashboardMetrics?.mttcMinutes != null ? `${dashboardMetrics.mttcMinutes.toFixed(1)} min` : 'METRIC UNAVAILABLE'}
            <span
              className={`text-[12px] font-normal font-['JetBrains_Mono'] ${
                isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
              }`}
            >
              {dashboardMetrics?.mttcMinutes != null ? 'MTTC (backend)' : 'insufficient telemetry'}
            </span>
          </div>
          <div className={`text-[11px] mt-1 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
            Calculated from persisted containment timestamps
          </div>
        </div>

        <div
          className={`p-3 border transition-colors ${
            isLight
              ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm'
              : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
          }`}
        >
          <div
            className={`font-['JetBrains_Mono'] text-[10px] font-semibold ${
              isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/85'
            }`}
          >
            SENSOR MESH HEALTH
          </div>
          <div
            className={`font-['Space_Grotesk'] text-[26px] font-bold mt-1 ${
              isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
            }`}
          >
            {dashboardMetrics?.sensorHealth ?? 'METRIC UNAVAILABLE'}
          </div>
          <div className={`text-[11px] mt-1 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
            Sensor sources: {dashboardMetrics?.sensorSources ?? 'unavailable'}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Kill-Chain Matrix */}
      <div
        className={`p-3 border space-y-2 transition-colors ${
          isLight
            ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm'
            : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
        }`}
      >
        <div className="flex justify-between items-center">
          <span
            className={`font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 ${
              isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
            }`}
          >
            <span className="material-symbols-outlined text-[16px] text-[#ef4444]">timeline</span>
            ENTERPRISE KILL-CHAIN ADVERSARY PROGRESSION
          </span>
          <span
            className={`font-['JetBrains_Mono'] text-[10px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}
          >
            CORRELATED WITH MITRE ATT&CK MATRIX v14
          </span>
        </div>
        <div className="grid grid-cols-8 gap-1.5 pt-1">
          {killChainStages.map((stage) => (
            <div
              key={stage.name}
              className={`p-2 border text-center transition-all ${
                stage.critical
                  ? isLight
                    ? 'bg-[#fee2e2] border-[#dc2626] text-[#991b1b] shadow-sm'
                    : 'bg-[#7f1d1d]/60 border-[#ef4444] text-[#ffffff] shadow-[0_0_8px_rgba(239,68,68,0.3)]'
                  : stage.active
                  ? isLight
                    ? 'bg-[#fef2f2] border-[#fca5a5] text-[#b91c1c]'
                    : 'bg-[#2b080c] border-[#ef4444]/70 text-[#ff8080]'
                  : isLight
                  ? 'bg-[#f8fafc] border-[#e2e8f0] text-[#94a3b8]'
                  : 'bg-[#000000] border-[#3b0d11]/70 text-[#6b7280]'
              }`}
            >
              <div className="font-['JetBrains_Mono'] text-[18px] font-bold">
                {stage.count}
              </div>
              <div className="text-[10px] font-['Space_Grotesk'] font-medium mt-1 leading-tight">
                {stage.name}
              </div>
              {stage.critical && (
                <span className="inline-block mt-1 w-1.5 h-1.5 rounded-full bg-[#ef4444] pulse-beacon" />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Two-Column Middle Section: Threat Radar & Active Incidents */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4 items-start">
        {/* Radar & Autonomous Vector Scanner */}
        <div className="xl:col-span-7">
          <AutonomousVectorRadar
            events={events}
            theme={theme}
            onSelectIncident={onSelectIncident}
            onToggleExpand={() => setIsRadarModalOpen(true)}
          />
        </div>

        {/* Active Incidents List */}
        <div
          className={`xl:col-span-5 p-4 border space-y-3 transition-colors ${
            isLight
              ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm'
              : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
          }`}
        >
          <div className="flex justify-between items-center">
            <span
              className={`font-['JetBrains_Mono'] text-[11px] font-bold ${
                isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
              }`}
            >
              ACTIVE HIGH-CONFIDENCE INCIDENT DOSSIERS
            </span>
            <span
              className={`font-['JetBrains_Mono'] text-[10px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}
            >
              SORTED BY RISK CONFIDENCE
            </span>
          </div>

          <div className="space-y-2">
            {incidents.map((inc) => (
              <div
                key={inc.id}
                onClick={() => onSelectIncident(inc.id)}
                className={`p-3 border transition-colors cursor-pointer flex items-center justify-between ${
                  inc.status === 'ACTIVE_CONTAINMENT'
                    ? isLight
                      ? 'bg-[#fee2e2]/60 border-[#dc2626] hover:bg-[#fee2e2]'
                      : 'bg-[#1e0508] border-[#ef4444] hover:bg-[#2b080d]'
                    : isLight
                    ? 'bg-[#f8fafc] border-[#e2e8f0] hover:border-[#dc2626]'
                    : 'bg-[#000000] border-[#7f1d1d]/50 hover:border-[#ef4444]'
                }`}
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`font-['JetBrains_Mono'] text-[12px] font-bold ${
                        isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
                      }`}
                    >
                      {inc.id}
                    </span>
                    <span
                      className={`px-1.5 py-0.2 font-['JetBrains_Mono'] text-[9px] font-bold ${
                        inc.status === 'ACTIVE_CONTAINMENT'
                          ? 'bg-[#dc2626] text-[#ffffff]'
                          : isLight
                          ? 'bg-[#fee2e2] text-[#991b1b] border border-[#dc2626]'
                          : 'bg-[#7f1d1d]/80 text-[#fee2e2] border border-[#ef4444]/60'
                      }`}
                    >
                      {inc.status}
                    </span>
                    <span
                      className={`font-['Space_Grotesk'] text-[13px] font-medium ${
                        isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
                      }`}
                    >
                      {inc.title}
                    </span>
                  </div>
                  <div
                    className={`font-['Geist'] text-[11px] mt-1 ${
                      isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
                    }`}
                  >
                    {inc.description || "No incident description available."}
                  </div>
                </div>

                <div className="text-right shrink-0 ml-4 font-['JetBrains_Mono']">
                  <div className={`text-[18px] font-bold ${isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'}`}>
                    {inc.riskScore}
                  </div>
                  <div
                    className={`text-[9px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}
                  >
                    RISK SCORE
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Expanded Tactical Radar Command Modal */}
      {isRadarModalOpen && (
        <div className="fixed inset-0 z-50 bg-[#000000]/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 animate-in fade-in">
          <div className="w-full max-w-5xl max-h-[92vh] overflow-y-auto custom-scrollbar border border-[#dc2626] shadow-[0_0_50px_rgba(220,38,38,0.35)]">
            <AutonomousVectorRadar
              events={events}
              theme={theme}
              onSelectIncident={(id) => {
                setIsRadarModalOpen(false);
                onSelectIncident(id);
              }}
              isExpandedView={true}
              onToggleExpand={() => setIsRadarModalOpen(false)}
            />
          </div>
        </div>
      )}
    </div>
  );
};
