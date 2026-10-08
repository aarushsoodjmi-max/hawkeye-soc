import React from 'react';
import { ThemeMode } from '../types';
import { useSoc } from '../context/SocContext';

interface ContainmentModeBannerProps {
  isActive: boolean;
  onRelease: () => void;
  onViewContainmentDetails: () => void;
  theme?: ThemeMode;
}

export const ContainmentModeBanner: React.FC<ContainmentModeBannerProps> = ({
  isActive,
  onRelease,
  onViewContainmentDetails,
  theme = 'dark',
}) => {
  const { activeIncident } = useSoc();
  if (!isActive) return null;
  const isLight = theme === 'light';

  return (
    <div
      id="containment-mode-active-banner"
      className={`fixed top-14 left-60 right-0 z-20 px-4 py-1.5 flex items-center justify-between select-none border-b-2 transition-colors ${
        isLight
          ? 'bg-[#dc2626] border-[#991b1b] text-[#ffffff] shadow-[0_4px_14px_rgba(220,38,38,0.25)]'
          : 'bg-[#93000a] border-[#ff5451] text-[#ffdad6] shadow-[0_4px_20px_rgba(255,84,81,0.4)]'
      }`}
    >
      <div className="flex items-center gap-2">
        <span className="material-symbols-outlined text-[18px] text-[#ffffff] pulse-beacon">
          security
        </span>
        <span className="font-['Space_Grotesk'] text-[13px] font-bold tracking-wider uppercase">
          PERIMETER CONTAINMENT LOCKDOWN ACTIVE
        </span>
        <span className="text-[#ffffff]/60">|</span>
        <span className="font-['JetBrains_Mono'] text-[11px] text-[#ffffff]">
          {activeIncident?.id || 'Incident'} • Backend status: {activeIncident?.status || 'CONTAINED'}
        </span>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onViewContainmentDetails}
          className={`px-2 py-0.5 border font-['JetBrains_Mono'] text-[10px] font-bold transition-colors ${
            isLight
              ? 'bg-[#ffffff] text-[#991b1b] border-[#ffffff] hover:bg-[#fee2e2]'
              : 'bg-[#000000] border-[#ffdad6]/80 hover:bg-[#1a0508] text-[#ffdad6]'
          }`}
        >
          View Isolation Rules
        </button>
        <button
          type="button"
          onClick={onRelease}
          className={`px-2 py-0.5 font-['JetBrains_Mono'] text-[10px] font-bold transition-colors ${
            isLight
              ? 'bg-[#991b1b] text-[#ffffff] hover:bg-[#7f1d1d]'
              : 'bg-[#ffdad6] text-[#68000a] hover:bg-[#ffffff]'
          }`}
        >
          Release Containment
        </button>
      </div>
    </div>
  );
};

