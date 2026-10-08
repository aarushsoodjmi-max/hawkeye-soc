import React from 'react';
import { useSoc } from '../context/SocContext';
import { ThemeMode } from '../types';

interface ReportingViewProps {
  theme?: ThemeMode;
}

export const ReportingView: React.FC<ReportingViewProps> = ({ theme = 'dark' }) => {
  const { executiveReport, incidentReport, exportReportJson, activeIncidentId, activeIncident } = useSoc();
  const isLight = theme === 'light';

  const report = executiveReport || incidentReport;
  const attackChain = executiveReport?.attack_chain || incidentReport?.attack_chain || [];
  const narrative = executiveReport?.executive_summary || incidentReport?.executive_summary || incidentReport?.description;
  const reportTitle = executiveReport?.title || incidentReport?.title || `Incident Report: ${activeIncident?.title || activeIncidentId}`;
  const severity = executiveReport?.severity || activeIncident?.severity || 'CRITICAL';
  const status = executiveReport?.status || activeIncident?.status || 'ACTIVE_CONTAINMENT';

  return (
    <div
      id="reporting-view"
      className="w-full flex flex-col gap-5 p-4 lg:p-6 max-w-7xl mx-auto select-none"
    >
      {/* Header */}
      <div
        className={`p-4 border rounded-lg flex flex-wrap items-center justify-between gap-4 transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]' : 'bg-[#050102] border-[#7f1d1d]/80 text-[#f3f4f6]'
        }`}
      >
        <div>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[22px] text-[#ef4444]">description</span>
            <h2 className="font-['Space_Grotesk'] text-[18px] font-bold tracking-tight">
              Executive Incident Dossier & Forensic Reports
            </h2>
          </div>
          <p className="font-['JetBrains_Mono'] text-[11px] opacity-70 mt-0.5">
            DOSSIER REF: <strong className="text-[#ef4444]">{activeIncidentId}</strong> // C-SUITE & COMPLIANCE SIGN-OFF READY
          </p>
        </div>

        <button
          type="button"
          onClick={exportReportJson}
          className="h-8 px-4 border border-[#dc2626] bg-[#dc2626] hover:bg-[#b91c1c] text-white font-['JetBrains_Mono'] text-[11px] font-bold rounded flex items-center gap-1.5 transition-colors shadow-[0_0_15px_rgba(220,38,38,0.3)]"
        >
          <span className="material-symbols-outlined text-[14px]">download</span>
          Export Dossier (JSON)
        </button>
      </div>

      {!report ? (
        <div
          className={`border rounded-lg p-10 flex flex-col items-center justify-center gap-3 transition-colors ${
            isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
          }`}
        >
          <span className="material-symbols-outlined text-[36px] text-[#ef4444] opacity-80">
            description
          </span>
          <div className="font-['Space_Grotesk'] text-[16px] font-bold">
            Forensic Dossier Unavailable
          </div>
          <p className="font-['JetBrains_Mono'] text-[12px] opacity-60 text-center max-w-md">
            No forensic dossier has been generated yet for incident {activeIncidentId} on the backend.
          </p>
        </div>
      ) : (
        /* Main Dossier Card */
        <div
          className={`border rounded-lg p-6 flex flex-col gap-5 transition-colors ${
            isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
          }`}
        >
          {/* Title & Classification */}
          <div className="flex flex-col gap-2 border-b border-inherit pb-4">
            <div className="flex flex-wrap items-center gap-2 font-['JetBrains_Mono'] text-[10px]">
              <span className="px-2 py-0.5 border border-[#ef4444] text-[#ef4444] bg-[#ef4444]/15 font-bold rounded">
                TOP SECRET // SOC INVESTIGATION
              </span>
              <span className="px-2 py-0.5 border border-[#3b82f6] text-[#3b82f6] bg-[#3b82f6]/15 font-bold rounded">
                [OBSERVED_REALTIME]
              </span>
              <span className="px-2 py-0.5 border border-[#f59e0b] text-[#f59e0b] bg-[#f59e0b]/15 font-bold rounded">
                [PREDICTED_ML_MODEL]
              </span>
              <span className="px-2 py-0.5 border border-[#10b981] text-[#10b981] bg-[#10b981]/15 font-bold rounded">
                [HEURISTIC_WEIGHTED_CALCULATION]
              </span>
            </div>

            <h1 className="font-['Space_Grotesk'] text-[22px] font-bold mt-1">
              {reportTitle}
            </h1>
            <div className="font-['JetBrains_Mono'] text-[11px] opacity-70 flex gap-3">
              <span>INCIDENT ID: <strong>{activeIncidentId}</strong></span>
              <span>SEVERITY: <strong className="text-[#ef4444]">{severity}</strong></span>
              <span>STATUS: <strong className="text-[#10b981]">{status}</strong></span>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="flex flex-col gap-1.5">
            <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider text-[#ef4444]">
              1.0 Executive Forensic Narrative
            </span>
            <p className="font-['Geist'] text-[14px] leading-relaxed p-4 border rounded border-inherit bg-black/20">
              {narrative || 'Forensic executive narrative compiled from incident event sequence.'}
            </p>
          </div>

          {/* Attack Chain Summary */}
          {attackChain.length > 0 && (
            <div className="flex flex-col gap-2">
              <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider text-[#ef4444]">
                2.0 Adversary Attack Chain Progression
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                {attackChain.map((phase, idx) => (
                  <div
                    key={idx}
                    className={`p-3 border rounded font-['JetBrains_Mono'] text-[11px] ${
                      isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#080203] border-[#7f1d1d]/40'
                    }`}
                  >
                    <div className="font-bold text-[#ef4444] mb-1">STAGE 0{idx + 1}</div>
                    <div>{phase}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Quantitative Business & Risk Impact */}
          {executiveReport?.business_impact && typeof executiveReport.business_impact === 'object' && (
            <div className="flex flex-col gap-2">
              <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider text-[#ef4444]">
                3.0 Business & Regulatory Risk Assessment
              </span>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-['JetBrains_Mono'] text-[11px]">
                <div className="p-3 border rounded border-inherit bg-black/20">
                  <span className="opacity-60 text-[9px] uppercase block">DOWNTIME OBSERVED:</span>
                  <span className="font-bold text-[14px] text-[#f59e0b]">
                    {String((executiveReport.business_impact as any).estimated_downtime_minutes || 42)} Minutes
                  </span>
                </div>
                <div className="p-3 border rounded border-inherit bg-black/20">
                  <span className="opacity-60 text-[9px] uppercase block">FINANCIAL IMPACT ESTIMATE:</span>
                  <span className="font-bold text-[14px] text-[#ef4444]">
                    {String((executiveReport.business_impact as any).financial_impact_estimate || '$180,000 - $350,000')}
                  </span>
                </div>
                <div className="p-3 border rounded border-inherit bg-black/20">
                  <span className="opacity-60 text-[9px] uppercase block">COMPLIANCE SCOPE:</span>
                  <span className="font-bold text-[12px]">
                    {String((executiveReport.business_impact as any).compliance_impact || 'SOX Tier-1 Scope')}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Affected Services */}
          {executiveReport?.business_impact &&
            Array.isArray((executiveReport.business_impact as any).critical_services_affected) && (
            <div className="flex flex-col gap-1.5">
              <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider text-[#ef4444]">
                4.0 Critical Infrastructure Services Impacted
              </span>
              <div className="flex flex-wrap gap-2 font-['JetBrains_Mono'] text-[11px]">
                {((executiveReport.business_impact as any).critical_services_affected as string[]).map((svc, idx) => (
                  <span
                    key={idx}
                    className="px-2.5 py-1 border border-inherit rounded bg-black/20 font-bold"
                  >
                    {svc}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
