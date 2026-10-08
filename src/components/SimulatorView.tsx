import React from 'react';
import { ThemeMode } from '../types';

interface SimulatorViewProps {
  onInjectAttack: (type: 'mfa_replay' | 'lsass_dump' | 'c2_beacon' | 'dns_exfil' | 'iam_escalation') => void;
  onSpikeIngestion: () => void;
  onResetBuffer: () => void;
  onNavigateToLive: () => void;
  theme?: ThemeMode;
}

export const SimulatorView: React.FC<SimulatorViewProps> = ({
  onInjectAttack,
  onSpikeIngestion,
  onResetBuffer,
  onNavigateToLive,
  theme = 'dark',
}) => {
  const isLight = theme === 'light';

  // Each card runs exactly one backend scenario (see handleInjectAttack in App.tsx):
  // credential_theft, malware, ransomware, phishing, insider_threat.
  const scenarios = [
    {
      id: 'mfa_replay' as const,
      title: 'Credential Theft & MFA Bypass',
      severity: 'CRITICAL',
      source: 'Identity / EDR telemetry',
      desc: 'Failed-login burst, anomalous login, impossible travel, MFA bypass, LSASS credential dumping, then lateral movement.',
      tag: 'T1110, T1078, T1111, T1003, T1021 / Credential Access',
    },
    {
      id: 'c2_beacon' as const,
      title: 'Ransomware with C2 Key Exchange',
      severity: 'CRITICAL',
      source: 'EDR / Network telemetry',
      desc: 'Suspicious binary, shadow-copy deletion, backup service stopped, mass file encryption, ransom note, C2 beacon and spread to network shares.',
      tag: 'T1490, T1486, T1071, T1021.002 / Impact',
    },
    {
      id: 'lsass_dump' as const,
      title: 'Malware Execution & Process Injection',
      severity: 'HIGH',
      source: 'EDR / AV telemetry',
      desc: 'Dropped file, process injection, registry and scheduled-task persistence, C2 beacon, disabled security tooling and lateral spread attempt.',
      tag: 'T1055, T1547.001, T1053.005, T1071 / Persistence',
    },
    {
      id: 'dns_exfil' as const,
      title: 'Phishing to Macro Execution & C2',
      severity: 'HIGH',
      source: 'Mail / EDR / DNS telemetry',
      desc: 'Phishing email, credential-harvesting click, macro and PowerShell execution, outbound C2 beacon, DNS anomaly and mailbox forwarding rule.',
      tag: 'T1566, T1204, T1059, T1071.004 / Initial Access',
    },
    {
      id: 'iam_escalation' as const,
      title: 'Insider Data Exfiltration',
      severity: 'MEDIUM',
      source: 'DLP / Identity telemetry',
      desc: 'After-hours access, bulk download, removable media and personal cloud upload, data staging, then account access revoked.',
      tag: 'T1005, T1052.001, T1567.002, T1074.001 / Exfiltration',
    },
  ];

  return (
    <div
      id="simulator-screen"
      className={`fixed top-14 left-60 bottom-7 right-0 overflow-y-auto custom-scrollbar p-4 space-y-4 select-none transition-colors duration-200 ${
        isLight ? 'bg-[#f4f5f8] text-[#0f172a]' : 'bg-[#000000] text-[#e5e5e5]'
      }`}
    >
      <div className={`flex justify-between items-center pb-2 border-b transition-colors duration-200 ${
        isLight ? 'border-[#e2e8f0]' : 'border-[#7f1d1d]/60'
      }`}>
        <div>
          <div className="flex items-center gap-2">
            <h1 className={`font-['Space_Grotesk'] text-[24px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              Threat Simulation &amp; Red-Team Generator
            </h1>
            <span className={`px-2 py-0.5 border font-['JetBrains_Mono'] text-[10px] font-bold ${
              isLight
                ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c]'
                : 'bg-[#7f1d1d]/40 border-[#ef4444] text-[#fee2e2]'
            }`}>
              CONTROLLED ENVIRONMENT
            </span>
          </div>
          <p className={`font-['Geist'] text-[12px] mt-0.5 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
            Inject realistic adversary scenarios to exercise Hawkeye's backend detection, correlation, and containment pipeline.
          </p>
        </div>

        <button
          type="button"
          onClick={onNavigateToLive}
          className={`h-8 px-3 border font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-colors ${
            isLight
              ? 'border-[#dc2626] bg-[#fee2e2] text-[#b91c1c] hover:bg-[#dc2626] hover:text-[#ffffff]'
              : 'border-[#ef4444] bg-[#000000] text-[#ef4444] hover:bg-[#ef4444] hover:text-[#ffffff] shadow-[0_0_10px_rgba(239,68,68,0.2)]'
          }`}
        >
          <span className="material-symbols-outlined text-[15px]">stream</span>
          View Live Telemetry Stream
        </button>
      </div>

      {/* Global Controls */}
      <div className={`flex items-center gap-3 p-3 border transition-colors ${
        isLight
          ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm'
          : 'bg-[#050102] border-[#7f1d1d]/60'
      }`}>
        <span className={`font-['JetBrains_Mono'] text-[11px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
          STRESS TESTING &amp; SYSTEM CONTROLS:
        </span>
        <button
          type="button"
          onClick={onSpikeIngestion}
          className={`px-3 py-1.5 border font-['JetBrains_Mono'] text-[11px] font-semibold flex items-center gap-1 transition-colors ${
            isLight
              ? 'border-[#dc2626] bg-[#fee2e2] hover:bg-[#dc2626] text-[#991b1b] hover:text-[#ffffff]'
              : 'border-[#ef4444] bg-[#7f1d1d]/30 hover:bg-[#ef4444] text-[#fee2e2] hover:text-[#ffffff]'
          }`}
        >
          <span className="material-symbols-outlined text-[14px]">speed</span>
          Run Malware Attack Scenario (backend)
        </button>
        <button
          type="button"
          onClick={onResetBuffer}
          className={`px-3 py-1.5 border font-['JetBrains_Mono'] text-[11px] font-semibold flex items-center gap-1 transition-colors ${
            isLight
              ? 'border-[#cbd5e1] hover:border-[#dc2626] bg-[#f8fafc] text-[#64748b] hover:text-[#0f172a]'
              : 'border-[#7f1d1d]/60 hover:border-[#ef4444] bg-[#000000] text-[#9ca3af] hover:text-[#ffffff]'
          }`}
        >
          <span className="material-symbols-outlined text-[14px]">restart_alt</span>
          Reset Telemetry Baseline
        </button>
      </div>

      {/* Scenario Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {scenarios.map((scen) => (
          <div
            key={scen.id}
            className={`p-4 border space-y-2 flex flex-col justify-between transition-colors ${
              isLight
                ? 'border-[#e2e8f0] bg-[#ffffff] hover:border-[#dc2626] shadow-sm'
                : 'border-[#7f1d1d]/60 bg-[#050102] hover:border-[#ef4444] shadow-[0_0_15px_rgba(0,0,0,0.8)]'
            }`}
          >
            <div>
              <div className="flex justify-between items-center">
                <span
                  className={`font-['JetBrains_Mono'] text-[10px] px-1.5 py-0.5 border font-bold ${
                    scen.severity === 'CRITICAL'
                      ? isLight
                        ? 'bg-[#fee2e2] border-[#dc2626] text-[#991b1b]'
                        : 'bg-[#7f1d1d] border-[#ef4444] text-[#ffffff]'
                      : scen.severity === 'HIGH'
                      ? isLight
                        ? 'bg-[#fef2f2] border-[#fca5a5] text-[#b91c1c]'
                        : 'bg-[#450a0a] border-[#dc2626] text-[#fca5a5]'
                      : isLight
                      ? 'bg-[#fef3c7] border-[#fcd34d] text-[#b45309]'
                      : 'bg-[#1a0508] border-[#ef4444]/60 text-[#ff8080]'
                  }`}
                >
                  {scen.severity}
                </span>
                <span className={`font-['JetBrains_Mono'] text-[10px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                  {scen.source}
                </span>
              </div>

              <div className={`font-['Space_Grotesk'] text-[16px] font-bold mt-2 ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                {scen.title}
              </div>

              <div className={`font-['Geist'] text-[12px] mt-1 leading-relaxed ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                {scen.desc}
              </div>

              <div className={`font-['JetBrains_Mono'] text-[10px] mt-2 ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                MITRE: {scen.tag}
              </div>
            </div>

            <div className={`pt-3 border-t flex justify-end ${isLight ? 'border-[#e2e8f0]' : 'border-[#7f1d1d]/40'}`}>
              <button
                type="button"
                onClick={() => onInjectAttack(scen.id)}
                className={`px-3 py-1.5 border font-['JetBrains_Mono'] text-[11px] font-bold flex items-center gap-1.5 transition-colors cursor-pointer ${
                  isLight
                    ? 'border-[#dc2626] bg-[#fee2e2] hover:bg-[#dc2626] text-[#b91c1c] hover:text-[#ffffff]'
                    : 'border-[#ef4444] bg-[#000000] hover:bg-[#ef4444] text-[#ef4444] hover:text-[#ffffff] shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                }`}
              >
                <span className="material-symbols-outlined text-[15px]">send</span>
                Inject Vector into Stream
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
