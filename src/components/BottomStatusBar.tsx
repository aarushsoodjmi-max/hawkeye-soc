import React from 'react';
import { ThemeMode } from '../types';

interface BottomStatusBarProps {
  onlineNodes?: number;
  totalNodes?: number;
  bufferPercent?: number | null;
  bufferUsedGB?: number | null;
  engineVersion?: string;
  theme?: ThemeMode;
  backendStatus?: 'checking' | 'connected' | 'unavailable';
}

export const BottomStatusBar: React.FC<BottomStatusBarProps> = ({
  onlineNodes,
  totalNodes,
  bufferPercent,
  bufferUsedGB,
  engineVersion = 'v4.1.1',
  theme = 'dark',
  backendStatus = 'checking',
}) => {
  const isLight = theme === 'light';

  return (
    <footer
      id="hawkeye-footer-status"
      className={`fixed bottom-0 left-60 right-0 h-7 border-t z-40 px-5 flex items-center justify-between font-['JetBrains_Mono'] text-[10px] tracking-wider select-none transition-colors duration-200 ${
        isLight
          ? 'bg-[#ffffff] border-[#e2e8f0] text-[#64748b]'
          : 'bg-[#000000] border-[#7f1d1d]/60 text-[#9ca3af]'
      }`}
    >
      <div className="flex items-center gap-3">
        <div className={`flex items-center gap-1.5 ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
          <span className="w-1.5 h-1.5 rounded-full bg-[#ef4444] pulse-beacon shadow-[0_0_6px_#ef4444]" />
          <span className="font-semibold">
            {backendStatus === 'connected'
              ? 'NODE MESH: LIVE BACKEND'
              : backendStatus === 'unavailable'
              ? 'NODE MESH: BACKEND UNAVAILABLE'
              : 'NODE MESH: CHECKING BACKEND'}
          </span>
        </div>
        <span className={isLight ? 'text-[#cbd5e1]' : 'text-[#7f1d1d]/60'}>•</span>
        <span className={`font-medium ${isLight ? 'text-[#dc2626]' : 'text-[#ff8080]'}`}>
          {backendStatus === 'connected' ? 'STATUS: CONNECTED' : backendStatus === 'unavailable' ? 'STATUS: BACKEND UNAVAILABLE' : 'STATUS: CHECKING'}
        </span>
        <span className={isLight ? 'text-[#cbd5e1]' : 'text-[#7f1d1d]/60'}>•</span>
        <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>
          BUFFER:{' '}
          {backendStatus === 'connected' ? (
            <span className="opacity-75 font-normal">Metric unavailable from backend</span>
          ) : (
            <>
              <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                {typeof bufferPercent === 'number' ? bufferPercent.toFixed(1) : 'N/A'}%
              </span>{' '}
              ({typeof bufferUsedGB === 'number' ? bufferUsedGB.toFixed(1) : 'N/A'}GB)
            </>
          )}
        </span>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1">
          <span className={isLight ? 'text-[#94a3b8]' : 'text-[#6b7280]'}>ENCRYPTION:</span>
          <span className={`font-semibold ${isLight ? 'text-[#0f172a]' : 'text-[#e5e5e5]'}`}>
            AES-256-GCM / TLS 1.3
          </span>
        </div>
        <span className={isLight ? 'text-[#cbd5e1]' : 'text-[#7f1d1d]/60'}>•</span>
        <div className="flex items-center gap-1">
          <span className={isLight ? 'text-[#94a3b8]' : 'text-[#6b7280]'}>HAWKEYE:</span>
          <span className={`font-bold tracking-wider ${isLight ? 'text-[#b91c1c]' : 'text-[#ff3b38] shadow-[0_0_8px_rgba(255,59,56,0.2)]'}`}>
            {engineVersion}
          </span>
        </div>
      </div>
    </footer>
  );
};
