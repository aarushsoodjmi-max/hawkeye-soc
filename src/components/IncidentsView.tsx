import React, { useState } from 'react';
import { IncidentRecord, ThemeMode } from '../types';

interface IncidentsViewProps {
  incidents: IncidentRecord[];
  activeIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  onNavigateToLive: () => void;
  theme?: ThemeMode;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  activeIncidentId,
  onSelectIncident,
  onNavigateToLive,
  theme = 'dark',
}) => {
  const isLight = theme === 'light';
  const selectedIncident =
    incidents.find((i) => i.id === activeIncidentId) || incidents[0];

  const [filterStatus, setFilterStatus] = useState<string>('ALL');

  if (!selectedIncident) {
    return (
      <div
        id="incidents-screen"
        className={`fixed top-14 left-60 bottom-7 right-0 flex flex-col items-center justify-center gap-2 select-none transition-colors duration-200 ${
          isLight ? 'bg-[#f4f5f8] text-[#0f172a]' : 'bg-[#000000] text-[#e5e1e5]'
        }`}
      >
        <span className="material-symbols-outlined text-[32px] text-[#dc2626]">
          shield_question
        </span>
        <span className="font-['Space_Grotesk'] text-[14px] font-bold">
          No Incidents in Workspace
        </span>
        <span className={`text-[11px] font-['JetBrains_Mono'] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
          Correlate an alert or run a scenario to populate the triage queue.
        </span>
        <button
          type="button"
          onClick={onNavigateToLive}
          className={`mt-2 h-7 px-3 border font-['JetBrains_Mono'] text-[11px] font-semibold flex items-center gap-1 transition-colors ${
            isLight
              ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c] hover:bg-[#dc2626] hover:text-[#ffffff]'
              : 'bg-[#7f1d1d]/40 border-[#ef4444] text-[#ffffff] hover:bg-[#ef4444]'
          }`}
        >
          <span className="material-symbols-outlined text-[14px]">stream</span>
          View Live Stream
        </button>
      </div>
    );
  }

  return (
    <div
      id="incidents-screen"
      className={`fixed top-14 left-60 bottom-7 right-0 overflow-hidden flex flex-col select-none transition-colors duration-200 ${
        isLight ? 'bg-[#f4f5f8] text-[#0f172a]' : 'bg-[#000000] text-[#e5e1e5]'
      }`}
    >
      {/* Header */}
      <div
        className={`px-4 py-2 border-b flex justify-between items-center shrink-0 transition-colors duration-200 ${
          isLight
            ? 'bg-[#ffffff] border-[#cbd5e1]'
            : 'bg-[#000000] border-[#7f1d1d]/60'
        }`}
      >
        <div>
          <div className="flex items-center gap-2">
            <h1
              className={`font-['Space_Grotesk'] text-[24px] font-semibold tracking-tight ${
                isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
              }`}
            >
              Incident Correlation & Triage
            </h1>
            <span
              className={`px-2 py-0.5 border font-['JetBrains_Mono'] text-[10px] font-bold ${
                isLight
                  ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c]'
                  : 'bg-[#7f1d1d]/60 border-[#ef4444] text-[#fee2e2] shadow-[0_0_8px_rgba(239,68,68,0.3)]'
              }`}
            >
              {incidents.filter(i => !['CLOSED','MITIGATED'].includes(String((i as any).status ?? '').toUpperCase())).length} ACTIVE CASES
            </span>
          </div>
          <p
            className={`font-['Geist'] text-[12px] mt-0.5 ${
              isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
            }`}
          >
            Automated multi-sensor alert clustering, attack kill-chain mapping, and containment logs.
          </p>
        </div>

        <button
          type="button"
          onClick={onNavigateToLive}
          className={`h-7 px-3 border font-['JetBrains_Mono'] text-[11px] font-semibold flex items-center gap-1 transition-colors ${
            isLight
              ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c] hover:bg-[#dc2626] hover:text-[#ffffff]'
              : 'bg-[#7f1d1d]/40 border-[#ef4444] text-[#ffffff] hover:bg-[#ef4444]'
          }`}
        >
          <span className="material-symbols-outlined text-[14px]">stream</span>
          View Live Stream
        </button>
      </div>

      {/* Main Split Layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left: Incident List */}
        <div
          className={`w-96 border-r flex flex-col overflow-y-auto custom-scrollbar transition-colors duration-200 ${
            isLight
              ? 'bg-[#ffffff] border-[#cbd5e1]'
              : 'bg-[#000000] border-[#7f1d1d]/50'
          }`}
        >
          <div
            className={`p-2 border-b flex items-center gap-1 font-['JetBrains_Mono'] text-[10px] ${
              isLight
                ? 'bg-[#f8fafc] border-[#cbd5e1]'
                : 'bg-[#000000] border-[#7f1d1d]/50'
            }`}
          >
            <span className={`font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>FILTER:</span>
            {['ALL', 'ACTIVE_CONTAINMENT', 'INVESTIGATING'].map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setFilterStatus(st)}
                className={`px-1.5 py-0.5 transition-colors ${
                  filterStatus === st
                    ? isLight
                      ? 'bg-[#fee2e2] border border-[#dc2626] text-[#b91c1c] font-bold'
                      : 'bg-[#7f1d1d] border border-[#ef4444] text-[#ffffff] font-bold'
                    : isLight
                    ? 'text-[#64748b] hover:text-[#0f172a]'
                    : 'text-[#9ca3af] hover:text-[#ffffff]'
                }`}
              >
                {st.replace('_', ' ')}
              </button>
            ))}
          </div>

          <div
            className={`divide-y ${isLight ? 'divide-[#e2e8f0]' : 'divide-[#1c070a]'}`}
          >
            {incidents
              .filter((inc) => filterStatus === 'ALL' || inc.status === filterStatus)
              .map((inc) => {
                const isSelected = selectedIncident.id === inc.id;
                return (
                  <div
                    key={inc.id}
                    onClick={() => onSelectIncident(inc.id)}
                    className={`p-3 cursor-pointer transition-colors ${
                      isSelected
                        ? isLight
                          ? 'bg-[#fee2e2]/50 border-l-2 border-[#dc2626]'
                          : 'bg-[#1a0508] border-l-2 border-[#ef4444]'
                        : isLight
                        ? 'hover:bg-[#f8fafc]'
                        : 'hover:bg-[#0d0204]'
                    }`}
                  >
                    <div className="flex justify-between items-start">
                      <span
                        className={`font-['Space_Grotesk'] text-[13px] font-bold ${
                          isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
                        }`}
                      >
                        {inc.id}
                      </span>
                      <span
                        className={`font-['JetBrains_Mono'] text-[10px] px-1.5 py-0.2 font-bold ${
                          inc.severity === 'CRITICAL'
                            ? isLight
                              ? 'bg-[#fee2e2] text-[#991b1b] border border-[#dc2626]'
                              : 'bg-[#7f1d1d] text-[#ffffff] border border-[#ef4444]'
                            : isLight
                            ? 'bg-[#fff1f2] text-[#be123c] border border-[#f43f5e]'
                            : 'bg-[#3b080c] text-[#ff8080] border border-[#ef4444]/50'
                        }`}
                      >
                        RISK {inc.riskScore}
                      </span>
                    </div>

                    <div
                      className={`font-['Geist'] text-[12px] font-medium mt-1 ${
                        isLight ? 'text-[#334155]' : 'text-[#e5e5e5]'
                      }`}
                    >
                      {inc.title}
                    </div>

                    <div
                      className={`mt-2 flex items-center justify-between font-['JetBrains_Mono'] text-[10px] ${
                        isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
                      }`}
                    >
                      <span>{inc.killChainStage}</span>
                      <span className={`font-semibold ${isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'}`}>
                        {inc.status}
                      </span>
                    </div>
                  </div>
                );
              })}
          </div>
        </div>

        {/* Right: Incident Deep Dive Workspace */}
        <div
          className={`flex-1 overflow-y-auto custom-scrollbar p-4 space-y-4 transition-colors duration-200 ${
            isLight ? 'bg-[#f4f5f8]' : 'bg-[#000000]'
          }`}
        >
          {/* Header Card */}
          <div
            className={`p-4 border space-y-2 transition-colors ${
              isLight
                ? 'bg-[#ffffff] border-[#cbd5e1] shadow-xs'
                : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
            }`}
          >
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <span
                  className={`font-['JetBrains_Mono'] text-[12px] px-2 py-0.5 font-bold ${
                    isLight
                      ? 'bg-[#fee2e2] text-[#991b1b] border border-[#dc2626]'
                      : 'bg-[#7f1d1d] text-[#ffffff] border border-[#ef4444]'
                  }`}
                >
                  {selectedIncident.severity}
                </span>
                <h2
                  className={`font-['Space_Grotesk'] text-[20px] font-bold ${
                    isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
                  }`}
                >
                  {selectedIncident.id}: {selectedIncident.title}
                </h2>
              </div>
              <span
                className={`font-['JetBrains_Mono'] text-[11px] font-semibold ${
                  isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
                }`}
              >
                Assigned: {selectedIncident.assignedTo}
              </span>
            </div>

            <div className="grid grid-cols-4 gap-3 pt-2 text-[11px] font-['JetBrains_Mono']">
              <div
                className={`p-2 border ${
                  isLight
                    ? 'bg-[#f8fafc] border-[#e2e8f0]'
                    : 'bg-[#000000] border-[#7f1d1d]/50'
                }`}
              >
                <div className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>
                  PRIMARY ATTACK VECTOR
                </div>
                <div
                  className={`font-bold mt-0.5 ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}
                >
                  {selectedIncident.primaryVector}
                </div>
              </div>
              <div
                className={`p-2 border ${
                  isLight
                    ? 'bg-[#f8fafc] border-[#e2e8f0]'
                    : 'bg-[#000000] border-[#7f1d1d]/50'
                }`}
              >
                <div className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>
                  KILL-CHAIN PHASE
                </div>
                <div
                  className={`font-bold mt-0.5 ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}
                >
                  {selectedIncident.killChainStage}
                </div>
              </div>
              <div
                className={`p-2 border ${
                  isLight
                    ? 'bg-[#f8fafc] border-[#e2e8f0]'
                    : 'bg-[#000000] border-[#7f1d1d]/50'
                }`}
              >
                <div className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>
                  IMPACTED PRINCIPALS
                </div>
                <div
                  className={`font-bold mt-0.5 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}
                >
                  {selectedIncident.impactedEntities.users.join(', ')}
                </div>
              </div>
              <div
                className={`p-2 border ${
                  isLight
                    ? 'bg-[#f8fafc] border-[#e2e8f0]'
                    : 'bg-[#000000] border-[#7f1d1d]/50'
                }`}
              >
                <div className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>
                  HOSTS / ASSETS
                </div>
                <div
                  className={`font-bold mt-0.5 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}
                >
                  {selectedIncident.impactedEntities.hosts.join(', ')}
                </div>
              </div>
            </div>
          </div>

          {/* Autonomous Actions Timeline */}
          <div
            className={`p-4 border space-y-3 transition-colors ${
              isLight
                ? 'bg-[#ffffff] border-[#cbd5e1] shadow-xs'
                : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
            }`}
          >
            <div className="flex justify-between items-center">
              <span
                className={`font-['JetBrains_Mono'] text-[12px] font-bold flex items-center gap-1.5 ${
                  isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
                }`}
              >
                <span className={`material-symbols-outlined text-[16px] ${
                  isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'
                }`}>
                  smart_toy
                </span>
                AUTONOMOUS DEFENSE AUDIT TRAIL
              </span>
              <span
                className={`font-['JetBrains_Mono'] text-[10px] ${
                  isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
                }`}
              >
                ENFORCED VIA ZERO-TRUST FABRIC
              </span>
            </div>

            <div className="space-y-2">
              {selectedIncident.autonomousActions.map((action, idx) => (
                <div
                  key={idx}
                  className={`p-2.5 border flex items-center justify-between font-['JetBrains_Mono'] text-[11px] ${
                    isLight
                      ? 'bg-[#f8fafc] border-[#e2e8f0]'
                      : 'bg-[#000000] border-[#7f1d1d]/50'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        action.status === 'COMPLETED'
                          ? isLight ? 'bg-[#16a34a]' : 'bg-[#ef4444]'
                          : isLight ? 'bg-[#dc2626]' : 'bg-[#dc2626]'
                      }`}
                    />
                    <span className={isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}>
                      {action.action}
                    </span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>
                      {action.timestamp}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 text-[10px] font-bold ${
                        action.status === 'COMPLETED'
                          ? isLight
                            ? 'bg-[#dcfce7] text-[#15803d] border border-[#86efac]'
                            : 'bg-[#7f1d1d] text-[#ffffff] border border-[#ef4444]'
                          : isLight
                          ? 'bg-[#fee2e2] text-[#991b1b] border border-[#fca5a5]'
                          : 'bg-[#450a0a] text-[#ff8080] border border-[#ef4444]/60'
                      }`}
                    >
                      {action.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* MITRE Techniques Badges */}
          <div
            className={`p-4 border space-y-2 transition-colors ${
              isLight
                ? 'bg-[#ffffff] border-[#cbd5e1] shadow-xs'
                : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
            }`}
          >
            <span
              className={`font-['JetBrains_Mono'] text-[11px] font-bold ${
                isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
              }`}
            >
              MAPPED MITRE ATT&CK TECHNIQUES
            </span>
            <div className="flex gap-2 flex-wrap pt-1">
              {selectedIncident.mitreTechniques.map((tech) => (
                <span
                  key={tech}
                  className={`px-2 py-1 border font-['JetBrains_Mono'] text-[11px] ${
                    isLight
                      ? 'bg-[#fee2e2]/60 border-[#dc2626] text-[#b91c1c]'
                      : 'bg-[#000000] border-[#ef4444]/70 text-[#ff8080]'
                  }`}
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
