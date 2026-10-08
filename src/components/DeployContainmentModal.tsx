import React, { useState } from 'react';
import { ThemeMode } from '../types';
import { useSoc } from '../context/SocContext';

interface DeployContainmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDeploy: (options: {
    isolateHosts: boolean;
    revokeTokens: boolean;
    bgpBlackhole: boolean;
    killProcesses: boolean;
  }) => void;
  activeTargetIp?: string;
  activeTargetHost?: string;
  theme?: ThemeMode;
}

export const DeployContainmentModal: React.FC<DeployContainmentModalProps> = ({
  isOpen,
  onClose,
  onDeploy,
  activeTargetIp,
  activeTargetHost,
  theme = 'dark',
}) => {
  const { activeIncident } = useSoc();
  const [isolateHosts, setIsolateHosts] = useState(true);
  const [revokeTokens, setRevokeTokens] = useState(true);
  const [bgpBlackhole, setBgpBlackhole] = useState(true);
  const [killProcesses, setKillProcesses] = useState(true);
  const [confirmed, setConfirmed] = useState(false);

  if (!isOpen) return null;

  const isLight = theme === 'light';

  const handleDeploy = () => {
    onDeploy({
      isolateHosts,
      revokeTokens,
      bgpBlackhole,
      killProcesses,
    });
    onClose();
  };

  return (
    <div
      id="modal-deploy-containment"
      className="fixed inset-0 z-50 bg-[#000000]/80 backdrop-blur-xs flex items-center justify-center p-4 select-none animate-in fade-in"
    >
      <div className={`w-full max-w-xl border-2 flex flex-col transition-colors ${
        isLight
          ? 'bg-[#ffffff] border-[#dc2626] shadow-[0_0_40px_rgba(220,38,38,0.2)]'
          : 'bg-[#000000] border-[#ef4444] shadow-[0_0_40px_rgba(239,68,68,0.35)]'
      }`}>
        {/* Header with tactical alert styling */}
        <div className={`h-14 px-4 border-b flex items-center justify-between ${
          isLight
            ? 'bg-[#fee2e2] border-[#dc2626] text-[#991b1b]'
            : 'bg-[#7f1d1d]/40 border-[#ef4444] text-[#fee2e2]'
        }`}>
          <div className="flex items-center gap-2.5">
            <span className={`w-7 h-7 flex items-center justify-center border shrink-0 ${
              isLight ? 'bg-[#fecaca] border-[#dc2626]' : 'bg-[#7f1d1d] border-[#ef4444]'
            }`}>
              <span className={`material-symbols-outlined text-[18px] ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                warning
              </span>
            </span>
            <div>
              <div className={`font-['Space_Grotesk'] text-[16px] font-bold leading-tight ${
                isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
              }`}>
                DEPLOY AUTONOMOUS CONTAINMENT
              </div>
              <div className={`font-['JetBrains_Mono'] text-[10px] ${
                isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
              }`}>
                HIGH-CONSEQUENCE TACTICAL INTERVENTION DIRECTIVE
              </div>
            </div>
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

        {/* Content */}
        <div className="p-4 space-y-4">
          <div className={`p-3 border text-[12px] space-y-1 ${
            isLight
              ? 'bg-[#f8fafc] border-[#e2e8f0]'
              : 'bg-[#050102] border-[#7f1d1d]/60'
          }`}>
            <div className={`font-['JetBrains_Mono'] text-[10px] font-bold ${
              isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
            }`}>
              TARGET PARAMETERS
            </div>
            <div className="flex justify-between font-['JetBrains_Mono']">
              <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>Primary Breached Host:</span>
              <span className={`font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>{activeTargetHost || 'Not available'}</span>
            </div>
            <div className="flex justify-between font-['JetBrains_Mono']">
              <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>Compromised Subnet / IP:</span>
              <span className={`font-bold ${isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'}`}>{activeTargetIp || 'Not available'}</span>
            </div>
            <div className="flex justify-between font-['JetBrains_Mono']">
              <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>Correlated Case:</span>
              <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>{activeIncident?.id || 'No incident selected'} (RISK {activeIncident?.riskScore ?? 'N/A'})</span>
            </div>
          </div>

          {/* Intervention Directives Checkboxes */}
          <div className="space-y-2">
            <div className={`font-['JetBrains_Mono'] text-[11px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              SELECT CONTAINMENT DIRECTIVES:
            </div>

            <label className={`flex items-start gap-2.5 p-2 border cursor-pointer transition-colors ${
              isLight
                ? 'bg-[#ffffff] border-[#e2e8f0] hover:border-[#dc2626]'
                : 'bg-[#050102] border-[#7f1d1d]/40 hover:border-[#ef4444]'
            }`}>
              <input
                type="checkbox"
                checked={isolateHosts}
                onChange={(e) => setIsolateHosts(e.target.checked)}
                className="mt-0.5 accent-[#dc2626]"
              />
              <div>
                <div className={`font-['JetBrains_Mono'] text-[11px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                  Isolate Endpoints (CrowdStrike Zero-Trust Host Quarantine)
                </div>
                <div className={`text-[11px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                  Disconnects network stack on {activeTargetHost || 'Not available'}, permitting only Hawkeye sensor telemetry.
                </div>
              </div>
            </label>

            <label className={`flex items-start gap-2.5 p-2 border cursor-pointer transition-colors ${
              isLight
                ? 'bg-[#ffffff] border-[#e2e8f0] hover:border-[#dc2626]'
                : 'bg-[#050102] border-[#7f1d1d]/40 hover:border-[#ef4444]'
            }`}>
              <input
                type="checkbox"
                checked={revokeTokens}
                onChange={(e) => setRevokeTokens(e.target.checked)}
                className="mt-0.5 accent-[#dc2626]"
              />
              <div>
                <div className={`font-['JetBrains_Mono'] text-[11px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                  Revoke Okta Session Tokens & Kerberos TGTs
                </div>
                <div className={`text-[11px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                  Requests the backend to apply the configured identity containment policy for the selected incident.
                </div>
              </div>
            </label>

            <label className={`flex items-start gap-2.5 p-2 border cursor-pointer transition-colors ${
              isLight
                ? 'bg-[#ffffff] border-[#e2e8f0] hover:border-[#dc2626]'
                : 'bg-[#050102] border-[#7f1d1d]/40 hover:border-[#ef4444]'
            }`}>
              <input
                type="checkbox"
                checked={bgpBlackhole}
                onChange={(e) => setBgpBlackhole(e.target.checked)}
                className="mt-0.5 accent-[#dc2626]"
              />
              <div>
                <div className={`font-['JetBrains_Mono'] text-[11px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                  Perimeter BGP Blackhole / DNS Sinkhole for C2 Target
                </div>
                <div className={`text-[11px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                  Requests the backend to apply the configured perimeter containment policy for the selected incident.
                </div>
              </div>
            </label>

            <label className={`flex items-start gap-2.5 p-2 border cursor-pointer transition-colors ${
              isLight
                ? 'bg-[#ffffff] border-[#e2e8f0] hover:border-[#dc2626]'
                : 'bg-[#050102] border-[#7f1d1d]/40 hover:border-[#ef4444]'
            }`}>
              <input
                type="checkbox"
                checked={killProcesses}
                onChange={(e) => setKillProcesses(e.target.checked)}
                className="mt-0.5 accent-[#dc2626]"
              />
              <div>
                <div className={`font-['JetBrains_Mono'] text-[11px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                  Terminate Malicious Process Subtree (Cobalt Strike / Injected Mem)
                </div>
                <div className={`text-[11px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                  Forcefully terminates rundll32 and suspended injected memory blocks.
                </div>
              </div>
            </label>
          </div>

          {/* Confirmation Checkbox */}
          <div className={`pt-2 border-t ${isLight ? 'border-[#e2e8f0]' : 'border-[#7f1d1d]/50'}`}>
            <label className={`flex items-center gap-2 cursor-pointer font-['JetBrains_Mono'] text-[11px] ${
              isLight ? 'text-[#0f172a]' : 'text-[#fee2e2]'
            }`}>
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="accent-[#dc2626]"
              />
              <span>I confirm autonomous execution of containment directives across enterprise infrastructure.</span>
            </label>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className={`px-3 py-1.5 border font-['JetBrains_Mono'] text-[11px] transition-colors ${
                isLight
                  ? 'bg-[#ffffff] border-[#cbd5e1] text-[#64748b] hover:text-[#0f172a] hover:border-[#dc2626]'
                  : 'bg-[#000000] border-[#7f1d1d]/60 text-[#9ca3af] hover:text-[#ffffff] hover:border-[#ef4444]'
              }`}
            >
              Cancel
            </button>
            <button
              type="button"
              id="btn-execute-containment-action"
              disabled={!confirmed}
              onClick={handleDeploy}
              className={`px-4 py-1.5 font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-all ${
                confirmed
                  ? isLight
                    ? 'bg-[#dc2626] hover:bg-[#b91c1c] text-[#ffffff] border border-[#dc2626] shadow-[0_0_15px_rgba(220,38,38,0.35)] cursor-pointer'
                    : 'bg-[#dc2626] hover:bg-[#ef4444] text-[#ffffff] border border-[#ef4444] shadow-[0_0_15px_rgba(239,68,68,0.5)] cursor-pointer'
                  : isLight
                  ? 'bg-[#f1f5f9] border border-[#cbd5e1] text-[#94a3b8] cursor-not-allowed'
                  : 'bg-[#1a0508] border border-[#7f1d1d]/30 text-[#6b7280] cursor-not-allowed'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">lock</span>
              Execute Containment Directives
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
