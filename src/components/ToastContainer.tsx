import React from 'react';
import { useSoc } from '../context/SocContext';
import { ThemeMode } from '../types';

interface ToastContainerProps {
  theme?: ThemeMode;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ theme = 'dark' }) => {
  const { toasts, removeToast } = useSoc();
  const isLight = theme === 'light';

  if (!toasts.length) return null;

  return (
    <div
      id="hawkeye-toast-container"
      className="fixed bottom-9 right-4 z-50 flex flex-col gap-2 max-w-md w-full pointer-events-none"
    >
      {toasts.map((toast) => {
        const borderColors = {
          info: isLight ? 'border-[#3b82f6] bg-[#eff6ff] text-[#1e3a8a]' : 'border-[#3b82f6]/60 bg-[#081325]/95 text-[#bfdbfe]',
          success: isLight ? 'border-[#10b981] bg-[#ecfdf5] text-[#064e3b]' : 'border-[#10b981]/60 bg-[#041a12]/95 text-[#a7f3d0]',
          warning: isLight ? 'border-[#f59e0b] bg-[#fffbeb] text-[#78350f]' : 'border-[#f59e0b]/60 bg-[#1c1204]/95 text-[#fde68a]',
          error: isLight ? 'border-[#ef4444] bg-[#fef2f2] text-[#7f1d1d]' : 'border-[#ef4444]/70 bg-[#1a0507]/95 text-[#fecaca]',
          critical: isLight ? 'border-[#dc2626] bg-[#fee2e2] text-[#991b1b]' : 'border-[#dc2626] bg-[#2a0408]/95 text-[#fee2e2] shadow-[0_0_15px_rgba(239,68,68,0.4)]',
        }[toast.type];

        const iconNames = {
          info: 'info',
          success: 'check_circle',
          warning: 'warning',
          error: 'error',
          critical: 'emergency_home',
        }[toast.type];

        const iconColors = {
          info: 'text-[#3b82f6]',
          success: 'text-[#10b981]',
          warning: 'text-[#f59e0b]',
          error: 'text-[#ef4444]',
          critical: 'text-[#ef4444] animate-pulse',
        }[toast.type];

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto border backdrop-blur-md p-3 rounded shadow-lg transition-all flex items-start justify-between gap-3 ${borderColors}`}
          >
            <div className="flex items-start gap-2.5">
              <span className={`material-symbols-outlined text-[18px] shrink-0 mt-0.5 ${iconColors}`}>
                {iconNames}
              </span>
              <div className="flex flex-col">
                <span className="font-['Space_Grotesk'] text-[13px] font-bold leading-tight">
                  {toast.title}
                </span>
                {toast.description && (
                  <span className="font-['JetBrains_Mono'] text-[11px] opacity-90 mt-0.5 leading-snug">
                    {toast.description}
                  </span>
                )}
                <span className="font-['JetBrains_Mono'] text-[9px] opacity-60 mt-1">
                  {toast.timestamp}
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={() => removeToast(toast.id)}
              className="text-current opacity-60 hover:opacity-100 transition-opacity p-0.5"
            >
              <span className="material-symbols-outlined text-[14px]">close</span>
            </button>
          </div>
        );
      })}
    </div>
  );
};
