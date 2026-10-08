import React, { useState } from 'react';
import { SecurityEvent, ThemeMode } from '../types';

interface RunQueryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRunQuery: (query: string) => void;
  events: SecurityEvent[];
  theme?: ThemeMode;
}

export const RunQueryModal: React.FC<RunQueryModalProps> = ({
  isOpen,
  onClose,
  onRunQuery,
  events,
  theme = 'dark',
}) => {
  const [query, setQuery] = useState(
    'source="Okta" | where severity == "CRITICAL" | project timestamp, principal, sourceIp, eventType'
  );
  const [results, setResults] = useState<SecurityEvent[] | null>(null);
  const [queryLatency, setQueryLatency] = useState<number | null>(null);

  if (!isOpen) return null;

  const isLight = theme === 'light';

  const sampleQueries = [
    {
      name: 'Active MFA Replays',
      q: 'source="Okta" eventType="MFA Session Replay" | sort by riskScore desc',
    },
    {
      name: 'Cobalt Strike C2 Beacons',
      q: 'source="Palo Alto FW" | where eventType contains "Cobalt Strike" | summarize count() by destination',
    },
    {
      name: 'Impossible GeoIP Velocity',
      q: 'securityContext.type == "geoip_travel" | project principal, sourceIp, details.speed',
    },
    {
      name: 'LSASS Injection Calls',
      q: 'source="CrowdStrike" target_process="lsass.exe" | sort by timestamp desc',
    },
  ];

  const handleExecute = () => {
    const startTime = performance.now();
    const lowerQ = query.toLowerCase();

    // Simple parser simulation against real events
    const matched = events.filter((e) => {
      if (lowerQ.includes('critical') && e.severity !== 'CRITICAL') return false;
      if (lowerQ.includes('high') && e.severity !== 'HIGH') return false;
      if (lowerQ.includes('okta') && e.source !== 'Okta') return false;
      if (lowerQ.includes('crowdstrike') && e.source !== 'CrowdStrike') return false;
      if (lowerQ.includes('palo alto') && e.source !== 'Palo Alto FW') return false;
      if (lowerQ.includes('lsass') && !e.eventType.includes('LSASS')) return false;
      if (lowerQ.includes('mfa') && !e.eventType.includes('MFA')) return false;
      if (lowerQ.includes('cobalt') && !e.eventType.includes('Cobalt')) return false;
      return true;
    });

    const endTime = performance.now();
    setQueryLatency(Math.max(0, Math.round(endTime - startTime)));
    setResults(matched);
    onRunQuery(query);
  };

  return (
    <div
      id="modal-run-query"
      className="fixed inset-0 z-50 bg-[#000000]/80 backdrop-blur-xs flex items-center justify-center p-4 select-none animate-in fade-in"
    >
      <div className={`w-full max-w-3xl border-2 flex flex-col max-h-[85vh] transition-colors ${
        isLight
          ? 'bg-[#ffffff] border-[#dc2626] shadow-[0_0_40px_rgba(220,38,38,0.2)]'
          : 'bg-[#000000] border-[#ef4444] shadow-[0_0_40px_rgba(239,68,68,0.35)]'
      }`}>
        {/* Header */}
        <div className={`h-12 px-4 border-b flex items-center justify-between ${
          isLight
            ? 'bg-[#fee2e2] border-[#dc2626]'
            : 'bg-[#7f1d1d]/40 border-[#ef4444]'
        }`}>
          <div className="flex items-center gap-2.5">
            <span className={`w-6 h-6 flex items-center justify-center border shrink-0 ${
              isLight ? 'bg-[#fecaca] border-[#dc2626] text-[#b91c1c]' : 'bg-[#7f1d1d] border-[#ef4444] text-[#fee2e2]'
            }`}>
              <span className="material-symbols-outlined text-[15px]">terminal</span>
            </span>
            <span className={`font-['Space_Grotesk'] text-[16px] font-bold ${
              isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
            }`}>
              HAWKEYE KQL / SPL Telemetry Query Engine
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className={`w-7 h-7 flex items-center justify-center border transition-colors ${
              isLight
                ? 'border-[#cbd5e1] bg-[#ffffff] text-[#64748b] hover:text-[#0f172a] hover:border-[#dc2626]'
                : 'border-[#7f1d1d]/60 bg-[#000000] text-[#9ca3af] hover:text-[#ffffff] hover:border-[#ef4444]'
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">close</span>
          </button>
        </div>

        {/* Body */}
        <div className="p-4 space-y-3 overflow-y-auto custom-scrollbar flex-1">
          {/* Pre-canned query chips */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`font-['JetBrains_Mono'] text-[10px] font-bold ${
              isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
            }`}>QUICK FILTERS:</span>
            {sampleQueries.map((item) => (
              <button
                key={item.name}
                type="button"
                onClick={() => setQuery(item.q)}
                className={`px-2 py-0.5 border font-['JetBrains_Mono'] text-[10px] transition-colors ${
                  isLight
                    ? 'bg-[#f8fafc] border-[#cbd5e1] hover:border-[#dc2626] text-[#475569] hover:text-[#0f172a]'
                    : 'bg-[#050102] border-[#7f1d1d]/60 hover:border-[#ef4444] text-[#9ca3af] hover:text-[#ffffff]'
                }`}
              >
                {item.name}
              </button>
            ))}
          </div>

          {/* Query Terminal Editor */}
          <div className={`border p-2 flex flex-col ${
            isLight
              ? 'bg-[#f8fafc] border-[#cbd5e1]'
              : 'bg-[#050102] border-[#7f1d1d]/60'
          }`}>
            <div className={`flex justify-between items-center pb-1 text-[10px] font-['JetBrains_Mono'] border-b mb-1.5 ${
              isLight ? 'text-[#64748b] border-[#e2e8f0]' : 'text-[#9ca3af] border-[#7f1d1d]/40'
            }`}>
              <span>QUERY SYNTAX: <strong className={isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}>HAWKEYE-QUERY-V4</strong></span>
              <span>INDEX: `telemetry.hawkeye.events.live`</span>
            </div>
            <textarea
              rows={3}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className={`w-full bg-transparent font-['JetBrains_Mono'] text-[12px] focus:outline-none resize-none leading-relaxed ${
                isLight ? 'text-[#0f172a]' : 'text-[#fee2e2]'
              }`}
            />
          </div>

          {/* Action Row */}
          <div className="flex items-center justify-between">
            <div className={`font-['JetBrains_Mono'] text-[11px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
              {queryLatency !== null ? (
                <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                  Local filtering completed in {queryLatency}ms • {results?.length || 0} records matched
                </span>
              ) : (
                'Supports pipe operators: | where | sort | project | count'
              )}
            </div>
            <button
              type="button"
              id="btn-execute-kql-query"
              onClick={handleExecute}
              className={`px-4 py-1.5 border font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-colors cursor-pointer ${
                isLight
                  ? 'bg-[#dc2626] hover:bg-[#b91c1c] text-[#ffffff] border-[#dc2626] shadow-[0_0_12px_rgba(220,38,38,0.25)]'
                  : 'bg-[#dc2626] hover:bg-[#ef4444] text-[#ffffff] border-[#ef4444] shadow-[0_0_12px_rgba(239,68,68,0.3)]'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">play_arrow</span>
              Execute Query
            </button>
          </div>

          {/* Results Table */}
          {results && (
            <div className={`mt-3 border ${
              isLight ? 'border-[#cbd5e1] bg-[#ffffff]' : 'border-[#7f1d1d]/60 bg-[#050102]'
            }`}>
              <div className={`px-3 py-1 border-b font-['JetBrains_Mono'] text-[10px] flex justify-between ${
                isLight
                  ? 'bg-[#f1f5f9] border-[#cbd5e1] text-[#64748b]'
                  : 'bg-[#000000] border-[#7f1d1d]/60 text-[#9ca3af]'
              }`}>
                <span>QUERY OUTPUT STREAM ({results.length})</span>
                <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>RETURN FORMAT: TABULAR</span>
              </div>
              <div className="max-h-56 overflow-y-auto custom-scrollbar">
                <table className="w-full text-left font-['JetBrains_Mono'] text-[11px]">
                  <thead className={`border-b text-[10px] ${
                    isLight
                      ? 'bg-[#f8fafc] border-[#cbd5e1] text-[#b91c1c]'
                      : 'bg-[#000000] border-[#7f1d1d]/60 text-[#ef4444]'
                  }`}>
                    <tr>
                      <th className="p-1.5">TIME</th>
                      <th className="p-1.5">SEV</th>
                      <th className="p-1.5">SOURCE</th>
                      <th className="p-1.5">EVENT</th>
                      <th className="p-1.5">PRINCIPAL</th>
                      <th className="p-1.5">IP</th>
                    </tr>
                  </thead>
                  <tbody className={`divide-y ${
                    isLight
                      ? 'divide-[#e2e8f0] text-[#0f172a]'
                      : 'divide-[#7f1d1d]/30 text-[#e5e5e5]'
                  }`}>
                    {results.map((r) => (
                      <tr key={r.id} className={isLight ? 'hover:bg-[#fee2e2]/40' : 'hover:bg-[#1a0508]'}>
                        <td className={`p-1.5 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>{r.timestamp}</td>
                        <td className={`p-1.5 font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>{r.severity}</td>
                        <td className="p-1.5">{r.source}</td>
                        <td className={`p-1.5 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>{r.eventType}</td>
                        <td className={`p-1.5 font-medium ${isLight ? 'text-[#b91c1c]' : 'text-[#f59e0b]'}`}>{r.principal}</td>
                        <td className={`p-1.5 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>{r.sourceIp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
