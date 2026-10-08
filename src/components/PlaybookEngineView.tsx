import React from 'react';
import { useSoc } from '../context/SocContext';
import { useAuth } from '../context/AuthContext';
import { ThemeMode } from '../types';

interface PlaybookEngineViewProps {
  theme?: ThemeMode;
}

export const PlaybookEngineView: React.FC<PlaybookEngineViewProps> = ({ theme = 'dark' }) => {
  const {
    backendStatus,
    activePlaybookSteps,
    executePlaybookStep,
    executeFullPlaybook,
    playbookExecutionState,
    auditLog,
    activeIncident,
  } = useSoc();
  const { canExecuteActions, role } = useAuth();
  const isLight = theme === 'light';

  return (
    <div
      id="playbook-engine-view"
      className="w-full flex flex-col gap-5 p-4 lg:p-6 max-w-7xl mx-auto select-none"
    >
      {/* Top Header */}
      <div
        className={`p-4 border rounded-lg flex flex-wrap items-center justify-between gap-4 transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]' : 'bg-[#050102] border-[#7f1d1d]/80 text-[#f3f4f6]'
        }`}
      >
        <div>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[22px] text-[#10b981]">checklist</span>
            <h2 className="font-['Space_Grotesk'] text-[18px] font-bold tracking-tight">
              SOAR Playbook Execution Engine
            </h2>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${backendStatus === 'connected' ? 'border-[#10b981] bg-[#10b981]/15 text-[#10b981]' : 'border-[#ef4444] bg-[#ef4444]/10 text-[#ef4444]'}`}>{backendStatus === 'connected' ? 'LIVE SOAR ENGINE' : backendStatus === 'unavailable' ? 'BACKEND UNAVAILABLE' : 'BACKEND CHECKING'}</span>
          </div>
          <p className="font-['JetBrains_Mono'] text-[11px] opacity-70 mt-0.5">
            ACTIVE PLAYBOOK: <strong className="text-[#ef4444]">{activePlaybookSteps.length ? (activePlaybookSteps[0]?.id || "backend-defined") : "None returned"}</strong> (Active Incident: {activeIncident?.id || "None"})
          </p>
        </div>

        <div className="flex items-center gap-2 font-['JetBrains_Mono'] text-[11px]">
          <span className="opacity-70">ROLE STATUS:</span>
          <span className="px-2 py-0.5 border border-[#ef4444] text-[#ef4444] bg-[#ef4444]/10 rounded font-bold uppercase">
            {role}
          </span>
          <button
            type="button"
            disabled={!canExecuteActions}
            onClick={() => executeFullPlaybook(activePlaybookSteps[0]?.id || '')}
            className="h-8 px-4 border border-[#16a34a] bg-[#16a34a] hover:bg-[#15803d] disabled:opacity-50 text-white font-bold rounded flex items-center gap-1.5 transition-colors shadow-[0_0_15px_rgba(22,163,74,0.3)]"
          >
            <span className="material-symbols-outlined text-[14px]">play_arrow</span>
            Execute Playbook
          </button>
        </div>
      </div>

      {/* Step Progression List */}
      <div
        className={`border rounded-lg overflow-hidden transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
        }`}
      >
        <div
          className={`p-3.5 border-b flex items-center justify-between ${
            isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#0a0203] border-[#7f1d1d]/60'
          }`}
        >
          <span className="font-['Space_Grotesk'] text-[14px] font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-[#ef4444]">linear_scale</span>
            Multi-Stage Containment & Eradication Sequence
          </span>
          <span className="font-['JetBrains_Mono'] text-[10px] text-[#10b981]">[IDEMPOTENT DISPATCH]</span>
        </div>

        <div className="divide-y divide-inherit">
          {activePlaybookSteps.map((step, idx) => {
            const isCompleted = step.status === 'COMPLETED';
            const isExecuting = step.status === 'EXECUTING';
            const isPending = step.status === 'PENDING';
            const isFailed = step.status === 'FAILED';

            return (
              <div
                key={step.id || idx}
                className="p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 font-['JetBrains_Mono'] text-[12px] hover:bg-black/10 transition-colors"
              >
                <div className="flex items-start sm:items-center gap-3">
                  <div
                    className={`w-7 h-7 rounded-full border flex items-center justify-center font-bold text-[11px] shrink-0 ${
                      isCompleted
                        ? 'border-[#10b981] bg-[#10b981]/20 text-[#10b981]'
                        : isExecuting
                        ? 'border-[#3b82f6] bg-[#3b82f6]/20 text-[#3b82f6] animate-spin'
                        : isPending
                        ? 'border-[#f59e0b] bg-[#f59e0b]/20 text-[#f59e0b]'
                        : 'border-inherit text-current opacity-60'
                    }`}
                  >
                    {isCompleted ? '✓' : idx + 1}
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-[13px]">{step.action_type}</span>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-bold border ${
                          isCompleted
                            ? 'border-[#10b981] text-[#10b981]'
                            : isExecuting
                            ? 'border-[#3b82f6] text-[#3b82f6]'
                            : isPending
                            ? 'border-[#f59e0b] text-[#f59e0b]'
                            : 'border-[#ef4444] text-[#ef4444]'
                        }`}
                      >
                        {step.status}
                      </span>
                      {step.verified === true && (
                        <span className="px-1.5 py-0.2 rounded text-[9px] font-bold border border-[#10b981] bg-[#10b981]/15 text-[#10b981]">
                          POST-CONDITION: VERIFIED
                        </span>
                      )}
                      {step.verified === false && isCompleted && (
                        <span className="px-1.5 py-0.2 rounded text-[9px] font-bold border border-[#f59e0b] bg-[#f59e0b]/15 text-[#f59e0b]">
                          POST-CONDITION: NOT VERIFIED
                        </span>
                      )}
                    </div>
                    <div className="text-[11px] opacity-80 mt-0.5">{step.description}</div>
                    <div className="text-[10px] opacity-60 mt-0.5">TARGET: {step.target}</div>
                    {step.result && (
                      <div className="text-[10px] opacity-80 mt-0.5 font-mono text-[#f59e0b]">
                        RESULT: {step.result}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
                  {step.executed_at && (
                    <span className="text-[10px] opacity-60">
                      {step.executed_at} ({step.executed_by || 'SOAR'})
                    </span>
                  )}

                  {isPending && (
                    <button
                      type="button"
                      disabled={!canExecuteActions}
                      onClick={() => executePlaybookStep(step.id || '')}
                      className="px-3 py-1.5 border border-[#ef4444] text-[#ef4444] hover:bg-[#ef4444] hover:text-white rounded text-[11px] font-bold transition-all shadow-[0_0_10px_rgba(239,68,68,0.2)]"
                    >
                      Authorize & Run Step
                    </button>
                  )}

                  {isCompleted && (
                    <span className="material-symbols-outlined text-[20px] text-[#10b981]">
                      check_circle
                    </span>
                  )}

                  {isFailed && (
                    <span className="material-symbols-outlined text-[20px] text-[#ef4444]">
                      cancel
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Audit Log Trail (Immutable Log Table) */}
      <div
        className={`border rounded-lg overflow-hidden transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
        }`}
      >
        <div
          className={`p-3.5 border-b flex items-center justify-between ${
            isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#0a0203] border-[#7f1d1d]/60'
          }`}
        >
          <span className="font-['Space_Grotesk'] text-[14px] font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-[#3b82f6]">history</span>
            Cryptographic SOAR Audit Log Trail
          </span>
          <span className="font-['JetBrains_Mono'] text-[10px] text-[#3b82f6]">[TAMPER-EVIDENT LEDGER]</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-[11px] font-['JetBrains_Mono'] divide-y divide-inherit">
            <thead>
              <tr className={isLight ? 'bg-[#f1f5f9] text-[#475569]' : 'bg-black/60 text-[#9ca3af]'}>
                <th className="p-3">AUDIT ID</th>
                <th className="p-3">TIMESTAMP</th>
                <th className="p-3">ACTION DISPATCHED</th>
                <th className="p-3">ACTOR / PRINCIPAL</th>
                <th className="p-3">ROLE</th>
                <th className="p-3">WORKSPACE</th>
                <th className="p-3">OUTCOME</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-inherit">
              {auditLog.map((log) => (
                <tr key={log.id} className="hover:bg-black/10 transition-colors">
                  <td className="p-3 font-bold text-[#3b82f6]">{log.id}</td>
                  <td className="p-3 opacity-80">{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td className="p-3 font-bold">{log.action}</td>
                  <td className="p-3 opacity-90">{log.actorId}</td>
                  <td className="p-3 uppercase font-bold">{log.role}</td>
                  <td className="p-3 opacity-70">{log.workspaceId}</td>
                  <td className="p-3">
                    <span
                      className={`px-1.5 py-0.2 rounded text-[9px] font-bold border ${
                        log.outcome === 'SUCCESS'
                          ? 'border-[#10b981] text-[#10b981] bg-[#10b981]/10'
                          : 'border-[#ef4444] text-[#ef4444] bg-[#ef4444]/10'
                      }`}
                    >
                      {log.outcome}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
