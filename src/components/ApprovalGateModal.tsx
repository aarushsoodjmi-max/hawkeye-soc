import React from 'react';
import { useSoc } from '../context/SocContext';
import { useAuth } from '../context/AuthContext';
import { ThemeMode } from '../types';

interface ApprovalGateModalProps {
  isOpen: boolean;
  onClose?: () => void;
  onConfirm?: () => void;
  onCancel?: () => void;
  request?: any;
  theme?: ThemeMode;
}

export const ApprovalGateModal: React.FC<ApprovalGateModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  onCancel,
  theme = 'dark',
}) => {
  const { pendingApprovalAction, approvePendingAction, rejectPendingAction, playbookExecutionState } = useSoc();
  const { role, user, canExecuteActions } = useAuth();
  const isLight = theme === 'light';

  if (!isOpen || !pendingApprovalAction) return null;

  return (
    <div
      id="approval-gate-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md select-none"
    >
      <div
        className={`w-full max-w-xl border rounded-lg overflow-hidden shadow-2xl transition-colors duration-200 ${
          isLight
            ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]'
            : 'bg-[#060102] border-[#dc2626]/80 text-[#f3f4f6] shadow-[0_0_50px_rgba(220,38,38,0.35)]'
        }`}
      >
        {/* Header with High-Alert Indicator */}
        <div
          className={`p-4 border-b flex items-center justify-between ${
            isLight ? 'bg-[#fee2e2] border-[#fca5a5]' : 'bg-[#1e0205] border-[#ef4444]/60'
          }`}
        >
          <div className="flex items-center gap-2.5">
            <span className="material-symbols-outlined text-[22px] text-[#dc2626] animate-pulse">
              shield_with_heart
            </span>
            <div>
              <h2 className="font-['Space_Grotesk'] text-[17px] font-bold tracking-tight text-[#dc2626]">
                Human Operator Approval Gate
              </h2>
              <p className="font-['JetBrains_Mono'] text-[10px] text-current opacity-80 uppercase tracking-wider">
                SAFETY INVARIANT // EXPLICIT AUTHORIZATION REQUIRED BEFORE EXECUTION
              </p>
            </div>
          </div>

          <span className="px-2 py-0.5 border border-[#dc2626] bg-[#dc2626]/20 text-[#dc2626] text-[10px] font-['JetBrains_Mono'] font-bold rounded">
            GATE: ACTIVE
          </span>
        </div>

        {/* Content */}
        <div className="p-5 flex flex-col gap-4">
          {/* Action Details Summary */}
          <div
            className={`p-3 border rounded text-[12px] font-['JetBrains_Mono'] flex flex-col gap-2 ${
              isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#0f0305] border-[#7f1d1d]/60'
            }`}
          >
            <div className="flex justify-between items-center border-b border-inherit pb-2">
              <span className="opacity-70 text-[10px] uppercase">Action Title:</span>
              <span className="font-bold text-[#ef4444] text-[13px]">{pendingApprovalAction.title}</span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
              <div>
                <span className="opacity-60 block text-[9px] uppercase">TARGET ASSET / IDENTITY:</span>
                <span className="font-bold">{pendingApprovalAction.target}</span>
              </div>
              <div>
                <span className="opacity-60 block text-[9px] uppercase">INCIDENT ID:</span>
                <span className="font-bold text-[#3b82f6]">{pendingApprovalAction.incidentId}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-inherit">
              <span className="opacity-60 block text-[9px] uppercase">OPERATIONAL IMPACT ASSESSMENT:</span>
              <p className="mt-0.5 text-[11px] font-['Geist'] leading-relaxed opacity-90">
                {pendingApprovalAction.impact}
              </p>
            </div>

            <div className="pt-2 border-t border-inherit">
              <span className="opacity-60 block text-[9px] uppercase">ACTION CRYPTOGRAPHIC DIGEST:</span>
              <code className="mt-0.5 text-[10px] text-[#10b981] font-mono break-all block bg-black/40 p-1 rounded">
                {pendingApprovalAction.actionDigest}
              </code>
            </div>
          </div>

          {/* Execution Pipeline Status */}
          <div className="flex flex-col gap-1.5">
            <span className="font-['JetBrains_Mono'] text-[10px] uppercase font-bold tracking-wider opacity-70">
              State Progression Machine:
            </span>
            <div className="flex items-center gap-1 font-['JetBrains_Mono'] text-[10px]">
              {[
                { stage: 'SIMULATED', active: true, done: true },
                { stage: 'PENDING', active: playbookExecutionState === 'IDLE' || playbookExecutionState === 'PENDING_APPROVAL', done: playbookExecutionState === 'APPROVED' || playbookExecutionState === 'COMPLETED' },
                { stage: 'APPROVED', active: playbookExecutionState === 'APPROVED', done: playbookExecutionState === 'COMPLETED' },
                { stage: 'EXECUTED', active: playbookExecutionState === 'COMPLETED', done: playbookExecutionState === 'COMPLETED' },
              ].map((s, idx) => (
                <React.Fragment key={s.stage}>
                  <div
                    className={`px-2 py-1 rounded border text-center font-bold flex-1 ${
                      s.done
                        ? 'border-[#10b981] bg-[#10b981]/15 text-[#10b981]'
                        : s.active
                        ? 'border-[#f59e0b] bg-[#f59e0b]/15 text-[#f59e0b] animate-pulse'
                        : isLight
                        ? 'border-[#e2e8f0] text-[#94a3b8]'
                        : 'border-[#331114] text-[#6b7280]'
                    }`}
                  >
                    {s.stage}
                  </div>
                  {idx < 3 && <span className="opacity-40">→</span>}
                </React.Fragment>
              ))}
            </div>
          </div>

          {/* RBAC Verification Notice */}
          <div
            className={`p-3 border rounded text-[11px] font-['JetBrains_Mono'] flex items-center justify-between ${
              canExecuteActions
                ? isLight
                  ? 'border-[#10b981] bg-[#ecfdf5] text-[#064e3b]'
                  : 'border-[#10b981]/50 bg-[#062015] text-[#a7f3d0]'
                : isLight
                ? 'border-[#ef4444] bg-[#fef2f2] text-[#7f1d1d]'
                : 'border-[#ef4444]/60 bg-[#25080b] text-[#fecaca]'
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px]">
                {canExecuteActions ? 'verified_user' : 'gpp_bad'}
              </span>
              <span>
                CURRENT OPERATOR: <strong>{user?.sub}</strong> ({role.toUpperCase()})
              </span>
            </div>
            <span>
              {canExecuteActions ? 'AUTHORIZATION VERIFIED' : 'INSUFFICIENT PRIVILEGES'}
            </span>
          </div>

          {!canExecuteActions && (
            <p className="text-[11px] text-[#ef4444] font-['JetBrains_Mono']">
              ⚠ Current role ({role}) does not have permission to execute operational containment. Switch to <strong>Operator</strong> or <strong>Admin</strong> in the header or Login modal.
            </p>
          )}

          {/* Modal Action Buttons */}
          <div className="flex justify-end gap-2 pt-2 border-t border-inherit">
            <button
              type="button"
              onClick={rejectPendingAction}
              className={`h-9 px-4 border font-['JetBrains_Mono'] text-[11px] font-bold rounded transition-colors ${
                isLight
                  ? 'border-[#cbd5e1] hover:bg-[#fee2e2] text-[#dc2626]'
                  : 'border-[#7f1d1d] hover:bg-[#7f1d1d]/40 text-[#fca5a5]'
              }`}
            >
              Abort / Reject Action
            </button>

            <button
              type="button"
              disabled={!canExecuteActions}
              onClick={approvePendingAction}
              className="h-9 px-5 border border-[#16a34a] bg-[#16a34a] hover:bg-[#15803d] disabled:opacity-40 disabled:cursor-not-allowed text-white font-['JetBrains_Mono'] text-[11px] font-bold rounded flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(22,163,74,0.3)]"
            >
              <span className="material-symbols-outlined text-[16px]">check_circle</span>
              Approve & Dispatch Playbook
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
