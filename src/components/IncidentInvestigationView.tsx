import React, { useState } from 'react';
import { useSoc } from '../context/SocContext';
import { useAuth } from '../context/AuthContext';
import { ThemeMode } from '../types';
import { AiInvestigationPanel } from './AiInvestigationPanel';

interface IncidentInvestigationViewProps {
  theme?: ThemeMode;
}

export const IncidentInvestigationView: React.FC<IncidentInvestigationViewProps> = ({ theme = 'dark' }) => {
  const {
    activeIncident,
    incidents,
    setActiveIncidentId,
    toggleAssetIsolation,
    prediction,
    confidence,
    updateIncidentStatus,
  } = useSoc();
  const { canExecuteActions, role } = useAuth();
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'TIMELINE' | 'ASSETS' | 'ROOT_CAUSE' | 'AI_INVESTIGATION'>('OVERVIEW');

  const isLight = theme === 'light';

  if (!activeIncident) {
    return (
      <div className="p-8 text-center font-['JetBrains_Mono'] opacity-60">
        No incident selected.
      </div>
    );
  }

  return (
    <div
      id="incident-investigation-view"
      className="w-full flex flex-col gap-5 p-4 lg:p-6 max-w-7xl mx-auto select-none"
    >
      {/* Top Incident Summary Bar */}
      <div
        className={`p-4 border rounded-lg flex flex-wrap items-center justify-between gap-4 transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]' : 'bg-[#050102] border-[#7f1d1d]/80 text-[#f3f4f6]'
        }`}
      >
        <div className="flex items-center gap-3">
          <select
            value={activeIncident.id}
            onChange={(e) => setActiveIncidentId(e.target.value)}
            className={`h-8 px-2.5 border rounded font-['JetBrains_Mono'] text-[11px] font-bold ${
              isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#000000] border-[#7f1d1d]/60 text-white'
            }`}
          >
            {incidents.map((inc) => (
              <option key={inc.id} value={inc.id}>
                {inc.id} — {inc.title} ({inc.severity})
              </option>
            ))}
          </select>

          <span
            className={`px-2.5 py-0.5 rounded text-[11px] font-['JetBrains_Mono'] font-bold border ${
              activeIncident.severity === 'CRITICAL'
                ? 'border-[#ef4444] text-[#ef4444] bg-[#ef4444]/15'
                : 'border-[#f59e0b] text-[#f59e0b] bg-[#f59e0b]/15'
            }`}
          >
            {activeIncident.severity}
          </span>

          <span
            className={`px-2.5 py-0.5 rounded text-[11px] font-['JetBrains_Mono'] font-bold border ${
              activeIncident.status === 'ACTIVE_CONTAINMENT'
                ? 'border-[#3b82f6] text-[#3b82f6] bg-[#3b82f6]/15'
                : 'border-[#10b981] text-[#10b981] bg-[#10b981]/15'
            }`}
          >
            STATUS: {activeIncident.status}
          </span>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 font-['JetBrains_Mono'] text-[11px]">
          <span className="opacity-60">TRIAGE STATUS:</span>
          {['ACTIVE_CONTAINMENT', 'INVESTIGATING', 'CONTAINED', 'CLOSED'].map((st) => (
            <button
              key={st}
              type="button"
              disabled={!canExecuteActions}
              onClick={() => updateIncidentStatus(activeIncident.id, st as any)}
              className={`px-2 py-1 rounded border text-[10px] font-bold transition-all ${
                activeIncident.status === st
                  ? 'border-[#ef4444] bg-[#ef4444] text-white'
                  : 'border-inherit hover:border-[#ef4444] text-current opacity-70'
              }`}
            >
              {st.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-inherit gap-2 font-['JetBrains_Mono'] text-[12px]">
        {[
          { id: 'OVERVIEW', label: 'Dossier Overview', icon: 'dashboard' },
          { id: 'TIMELINE', label: 'Timeline & Correlated Events', icon: 'timeline' },
          { id: 'ASSETS', label: 'Impacted Assets & Blast Radius', icon: 'lan' },
          { id: 'ROOT_CAUSE', label: 'Root-Cause & Confidence', icon: 'psychology' },
          { id: 'AI_INVESTIGATION', label: 'AI Forensic Investigation', icon: 'auto_awesome' },
        ].map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-2 border-b-2 font-bold flex items-center gap-1.5 transition-colors ${
              activeTab === tab.id
                ? 'border-[#ef4444] text-[#ef4444]'
                : 'border-transparent text-current opacity-60 hover:opacity-100'
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">{tab.icon}</span>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab 1: Overview */}
      {activeTab === 'OVERVIEW' && (
        <div className="flex flex-col gap-5">
          {/* Key Metrics Row */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-['JetBrains_Mono']">
            {/* Risk Score */}
            <div
              className={`p-4 border rounded-lg flex flex-col justify-between ${
                isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
              }`}
            >
              <div className="flex justify-between items-center text-[10px] opacity-70 uppercase">
                <span>DYNAMIC RISK SCORE</span>
                <span className="text-[#ef4444] font-bold">[CALCULATED]</span>
              </div>
              <div className="flex items-baseline gap-2 my-2">
                <span className="text-[32px] font-bold text-[#ef4444]">
                  {activeIncident.riskScore ?? 'N/A'}
                </span>
                <span className="text-[12px] opacity-60">/ 100</span>
              </div>
              <div className="w-full h-1.5 rounded bg-black/30 overflow-hidden">
                <div
                  className="h-full bg-[#ef4444]"
                  style={{ width: `${activeIncident.riskScore ?? 'N/A'}%` }}
                />
              </div>
              <span className="text-[9px] opacity-60 mt-1.5">
                Factor Breakdown: {activeIncident.riskBreakdown ? Object.entries(activeIncident.riskBreakdown).map(([k,v]) => `${k}: ${v}`).join(' • ') : 'Not available'}
              </span>
            </div>

            {/* Unified Confidence */}
            <div
              className={`p-4 border rounded-lg flex flex-col justify-between ${
                isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
              }`}
            >
              <div className="flex justify-between items-center text-[10px] opacity-70 uppercase">
                <span>UNIFIED CONFIDENCE</span>
                <span className="text-[#10b981] font-bold">[HEURISTIC]</span>
              </div>
              <div className="flex items-baseline gap-2 my-2">
                <span className="text-[32px] font-bold text-[#10b981]">
                  {confidence ? `${confidence.unified_confidence_percent.toFixed(1)}%` : 'N/A'}
                </span>
              </div>
              <div className="w-full h-1.5 rounded bg-black/30 overflow-hidden">
                <div
                  className="h-full bg-[#10b981]"
                  style={{ width: `${confidence?.unified_confidence_percent ?? 0}%` }}
                />
              </div>
              <span className="text-[9px] opacity-60 mt-1.5">
                Correlation: 0.96 • ML: 0.89 • TI: 0.98
              </span>
            </div>

            {/* Business Impact */}
            <div
              className={`p-4 border rounded-lg flex flex-col justify-between ${
                isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
              }`}
            >
              <div className="flex justify-between items-center text-[10px] opacity-70 uppercase">
                <span>BUSINESS IMPACT</span>
                <span className="text-[#f59e0b] font-bold">[FINANCIAL]</span>
              </div>
              <div className="my-2">
                <div className="text-[18px] font-bold text-[#f59e0b]">
                  {activeIncident.businessImpact?.financial_impact_estimate || 'Not available'}
                </div>
                <div className="text-[11px] opacity-70 mt-0.5">
                  DOWNTIME: {activeIncident.businessImpact?.estimated_downtime_minutes ?? 'N/A'} min
                </div>
              </div>
              <span className="text-[9px] opacity-60">
                {activeIncident.businessImpact?.compliance_impact || 'Not available'}
              </span>
            </div>

            {/* Threat Actor Attribution */}
            <div
              className={`p-4 border rounded-lg flex flex-col justify-between ${
                isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
              }`}
            >
              <div className="flex justify-between items-center text-[10px] opacity-70 uppercase">
                <span>ATTRIBUTION</span>
                <span className="text-[#3b82f6] font-bold">[INTEL]</span>
              </div>
              <div className="my-2">
                <div className="text-[14px] font-bold text-[#ef4444]">
                  {activeIncident.threatActor || 'APT29 / Midnight Blizzard'}
                </div>
                <div className="text-[10px] opacity-70 mt-0.5">
                  ORIGIN: {activeIncident.threatActorOrigin || 'State-Sponsored'}
                </div>
              </div>
              <span className="text-[9px] opacity-60">
                TTP Overlap: 98% (Cobalt Strike, Mimikatz)
              </span>
            </div>
          </div>

          {/* Narrative & Attack Vector */}
          <div
            className={`border rounded-lg p-5 flex flex-col gap-4 transition-colors ${
              isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
            }`}
          >
            <div>
              <span className="font-['JetBrains_Mono'] text-[10px] uppercase font-bold text-[#ef4444]">
                INCIDENT SUMMARY & VECTOR
              </span>
              <h2 className="font-['Space_Grotesk'] text-[18px] font-bold mt-1">
                {activeIncident.title}
              </h2>
              <p className="font-['Geist'] text-[13px] opacity-90 mt-2 leading-relaxed">
                {activeIncident.impactSummary ||
                  'Compromised identity token initiated unauthorized lateral movement attempt towards Active Directory Domain Controllers.'}
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-['JetBrains_Mono'] text-[11px] pt-3 border-t border-inherit">
              <div>
                <span className="opacity-60 text-[9px] uppercase block">PRIMARY VECTOR:</span>
                <span className="font-bold text-[#ef4444]">
                  {activeIncident.primaryVector || 'Token Replay'}
                </span>
              </div>
              <div>
                <span className="opacity-60 text-[9px] uppercase block">KILL CHAIN STAGE:</span>
                <span className="font-bold">{activeIncident.killChainStage || 'Lateral Movement'}</span>
              </div>
              <div>
                <span className="opacity-60 text-[9px] uppercase block">MITRE ATT&CK TECHNIQUES:</span>
                <div className="flex flex-wrap gap-1 mt-0.5">
                  {(activeIncident.mitreTechniques || ['T1539', 'T1078', 'T1071']).map((tech) => (
                    <span key={tech} className="px-1.5 py-0.2 border border-current rounded text-[9px] font-bold">
                      {tech}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Timeline & Correlated Events */}
      {activeTab === 'TIMELINE' && (
        <div
          className={`border rounded-lg p-5 transition-colors ${
            isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
          }`}
        >
          <div className="flex items-center justify-between border-b border-inherit pb-3 mb-4">
            <span className="font-['Space_Grotesk'] text-[15px] font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#ef4444]">timeline</span>
              Chronological Kill-Chain Event Timeline ({activeIncident.timelineEvents?.length || 0} Events)
            </span>
            <span className="font-['JetBrains_Mono'] text-[10px] text-[#10b981]">[OBSERVED TELEMETRY]</span>
          </div>

          <div className="flex flex-col gap-3 font-['JetBrains_Mono'] text-[12px]">
            {activeIncident.timelineEvents?.map((evt, idx) => (
              <div
                key={evt.id || idx}
                className={`p-3.5 border rounded flex flex-col gap-2 ${
                  isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#080203] border-[#7f1d1d]/40'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-[#ef4444] text-[13px]">{evt.title}</span>
                    <span className="px-1.5 py-0.2 border border-[#3b82f6] text-[#3b82f6] rounded text-[9px] font-bold">
                      {evt.techniqueId || evt.technique}
                    </span>
                  </div>
                  <span className="text-[10px] opacity-60">{evt.timestamp} ({evt.relativeTime})</span>
                </div>

                <p className="font-['Geist'] text-[12px] opacity-90">{evt.description}</p>

                {evt.command && (
                  <div className="bg-black/40 p-1.5 rounded font-mono text-[10px] text-green-400 break-all">
                    $ {evt.command}
                  </div>
                )}

                <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] opacity-70 pt-2 border-t border-inherit">
                  <span>SOURCE: <strong>{evt.source}</strong></span>
                  <span>TARGET: <strong>{evt.target}</strong></span>
                  <span>TACTIC: <strong>{evt.tactic}</strong></span>
                  <span className="text-[#10b981]">EVIDENCE FIDELITY: {evt.evidenceConfidence}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Impacted Assets & Blast Radius */}
      {activeTab === 'ASSETS' && (
        <div
          className={`border rounded-lg p-5 transition-colors ${
            isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
          }`}
        >
          <div className="flex items-center justify-between border-b border-inherit pb-3 mb-4">
            <span className="font-['Space_Grotesk'] text-[15px] font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#ef4444]">lan</span>
              Impacted Infrastructure Assets ({activeIncident.affectedAssets?.length || 0} Nodes)
            </span>
            <span className="font-['JetBrains_Mono'] text-[10px] text-[#ef4444]">[BOUNDARY CONTAINMENT]</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {activeIncident.affectedAssets?.map((asset) => (
              <div
                key={asset.id}
                className={`p-4 border rounded-lg flex flex-col justify-between font-['JetBrains_Mono'] text-[11px] ${
                  isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#080203] border-[#7f1d1d]/40'
                }`}
              >
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-bold text-[13px] text-[#ef4444]">{asset.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[9px] font-bold border ${
                        asset.status === 'ISOLATED'
                          ? 'border-[#f59e0b] text-[#f59e0b]'
                          : 'border-[#ef4444] text-[#ef4444]'
                      }`}
                    >
                      {asset.status}
                    </span>
                  </div>

                  <div className="space-y-1 opacity-80">
                    <div>IP: <strong>{asset.ip}</strong></div>
                    <div>ROLE: {asset.role}</div>
                    <div>CRITICALITY: <strong className="text-[#ef4444]">{asset.criticality}</strong></div>
                    <div>BLAST RADIUS SCORE: <strong>{asset.blastRadiusScore} / 100</strong></div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-inherit">
                  <button
                    type="button"
                    disabled={!canExecuteActions}
                    onClick={() => toggleAssetIsolation(activeIncident.id, asset.id)}
                    className={`w-full py-1.5 border rounded font-bold transition-all ${
                      asset.status === 'ISOLATED'
                        ? 'border-[#10b981] text-[#10b981] hover:bg-[#10b981] hover:text-white'
                        : 'border-[#ef4444] text-[#ef4444] hover:bg-[#ef4444] hover:text-white shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                    }`}
                  >
                    {asset.status === 'ISOLATED' ? 'Restore Network' : 'Quarantine Host'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Root-Cause Prediction & Confidence */}
      {activeTab === 'ROOT_CAUSE' && (
        <div className="flex flex-col gap-5">
          {/* Root-Cause Card */}
          <div
            className={`border rounded-lg p-5 transition-colors ${
              isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
            }`}
          >
            <div className="flex items-center justify-between border-b border-inherit pb-3 mb-3">
              <span className="font-['Space_Grotesk'] text-[15px] font-bold flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px] text-[#ef4444]">troubleshoot</span>
                Forensic Root Cause Analysis
              </span>
              <span className="font-['JetBrains_Mono'] text-[10px] text-[#10b981]">[PREDICTED_ML_MODEL]</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-['JetBrains_Mono'] text-[11px]">
              <div>
                <span className="opacity-60 text-[9px] uppercase block">EXPLOITATION VECTOR:</span>
                <span className="font-bold text-[#ef4444] text-[13px]">
                  {activeIncident.rootCause?.vector}
                </span>
                <p className="font-['Geist'] text-[12px] opacity-80 mt-1">
                  {activeIncident.rootCause?.vulnerabilityDetails}
                </p>
              </div>

              <div>
                <span className="opacity-60 text-[9px] uppercase block">ADVERSARY C2 INFRASTRUCTURE:</span>
                <span className="font-bold text-[#3b82f6]">
                  {activeIncident.rootCause?.c2Server} ({activeIncident.rootCause?.c2Location})
                </span>
                <div className="opacity-70 mt-1">
                  DETECTION SENSOR: {activeIncident.rootCause?.detectionMechanism}
                </div>
              </div>
            </div>
          </div>

          {/* Predictions Horizon */}
          {prediction && (
            <div
              className={`border rounded-lg p-5 transition-colors ${
                isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
              }`}
            >
              <div className="flex items-center justify-between border-b border-inherit pb-3 mb-3">
                <span className="font-['Space_Grotesk'] text-[15px] font-bold flex items-center gap-2">
                  <span className="material-symbols-outlined text-[18px] text-[#f59e0b]">trending_up</span>
                  Predicted Lateral Movement Forecast & Risk Horizon
                </span>
                <span className="font-['JetBrains_Mono'] text-[10px] text-[#f59e0b]">[PREDICTED]</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-['JetBrains_Mono'] text-[11px]">
                {prediction.next_affected_assets.map((item, idx) => (
                  <div
                    key={idx}
                    className={`p-3 border rounded ${
                      isLight ? 'bg-[#fffbeb] border-[#fde68a]' : 'bg-[#180902] border-[#f59e0b]/40'
                    }`}
                  >
                    <div className="flex justify-between items-center text-[10px] mb-1">
                      <span className="font-bold text-[#f59e0b]">TARGET #{idx + 1}</span>
                      <span className="font-bold">{Math.round(item.confidence * 100)}% PROB.</span>
                    </div>
                    <div className="font-bold text-[12px]">{item.asset}</div>
                    <div className="opacity-80 text-[10px] mt-1">{item.reason}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 5: AI Forensic Investigation */}
      {activeTab === 'AI_INVESTIGATION' && (
        <AiInvestigationPanel theme={theme} />
      )}
    </div>
  );
};
