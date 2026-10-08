import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { HawkEyeLogo } from './HawkEyeLogo';
import { ShieldAlert, Terminal, ChevronRight, Activity } from 'lucide-react';

interface SplashScreenProps {
  onComplete: () => void;
  autoDismissTimeoutMs?: number;
}

export const SplashScreen: React.FC<SplashScreenProps> = ({
  onComplete,
  autoDismissTimeoutMs = 4600,
}) => {
  const [bootStep, setBootStep] = useState(0);
  const [progress, setProgress] = useState(0);

  const onCompleteRef = React.useRef(onComplete);
  onCompleteRef.current = onComplete;

  const bootMessages = [
    'BOOT // INITIALIZING HAWKEYE SOC OS V2.4...',
    'CALIBRATING OPTICAL THREAT CORRELATION RADAR...',
    'SYNCHRONIZING SIEM / EDR ACTIVE TELEMETRY STREAMS...',
    'DEFCON DEFENSE MATRIX ARMED & SECURED // SYSTEMS NOMINAL',
  ];

  useEffect(() => {
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(progressInterval);
          return 100;
        }
        return prev + 2;
      });
    }, 65);

    const step1 = setTimeout(() => setBootStep(1), 800);
    const step2 = setTimeout(() => setBootStep(2), 1700);
    const step3 = setTimeout(() => setBootStep(3), 2600);
    const dismissTimer = setTimeout(() => onCompleteRef.current(), autoDismissTimeoutMs);

    return () => {
      clearInterval(progressInterval);
      clearTimeout(step1);
      clearTimeout(step2);
      clearTimeout(step3);
      clearTimeout(dismissTimer);
    };
  }, [autoDismissTimeoutMs]);

  return (
    <motion.div
      id="hawkeye-splash-screen"
      key="hawkeye-splash-screen"
      initial={{ opacity: 1 }}
      exit={{ opacity: 0, scale: 1.02, filter: 'blur(8px)' }}
      transition={{ duration: 0.6, ease: 'easeInOut' }}
      onClick={onComplete}
      className="fixed inset-0 z-[99999] flex flex-col justify-between bg-black text-slate-100 overflow-hidden select-none cursor-pointer"
    >
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/3 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-red-950/20 rounded-full blur-[140px]" />
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage:
              'linear-gradient(#ff0033 1px, transparent 1px), linear-gradient(to right, #ff0033 1px, transparent 1px)',
            backgroundSize: '48px 48px',
          }}
        />
      </div>

      <div className="relative z-10 flex items-center justify-between px-6 py-5 border-b border-[#1c202a]/80 bg-black/70 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="flex h-7 w-7 items-center justify-center rounded crystal-facet-active text-red-400">
            <ShieldAlert className="h-4 w-4 crystal-icon-svg" />
          </div>
          <div>
            <span className="text-xs font-mono font-bold tracking-widest text-slate-300 uppercase">
              HAWKEYE SOC // COMMAND ENGINE
            </span>
            <span className="hidden sm:inline-block ml-3 text-[10px] font-mono text-red-400/90 border-l border-[#242936] pl-3">
              SECURE HANDSHAKE // 4096-BIT TLS
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
            </span>
            <span className="text-[11px] font-mono text-red-400 font-semibold tracking-wider">
              ACTIVE
            </span>
          </div>

          <button
            id="btn-skip-splash"
            onClick={(e) => {
              e.stopPropagation();
              onComplete();
            }}
            className="flex items-center gap-2 rounded border border-red-500/40 crystal-facet px-3.5 py-1.5 text-xs font-mono text-red-200 hover:text-white hover:border-red-400 transition cursor-pointer shadow-[0_0_15px_rgba(255,0,51,0.25)]"
          >
            <span>ENTER SOC</span>
            <span className="crystal-icon-badge w-4 h-4 crystal-gem-ruby">
              <ChevronRight className="h-3 w-3 text-red-200 crystal-icon-svg" />
            </span>
          </button>
        </div>
      </div>

      <div className="relative z-10 flex-1 flex flex-col items-center justify-center px-4 max-w-5xl w-full mx-auto my-auto">
        <div className="w-full max-w-4xl">
          <HawkEyeLogo
            variant="splash"
            animated={true}
            showText={true}
          />
        </div>

        <div className="mt-8 flex flex-col items-center text-center max-w-lg w-full">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 mb-2">
            <span className="crystal-icon-badge w-4 h-4 crystal-gem-ruby">
              <Terminal className="h-3 w-3 text-red-400 animate-pulse crystal-icon-svg" />
            </span>
            <span>{bootMessages[bootStep]}</span>
          </div>

          <div className="w-full h-1.5 bg-[#12151e] rounded-full overflow-hidden border border-[#212735] relative">
            <motion.div
              className="h-full bg-gradient-to-r from-red-700 via-red-500 to-red-400 shadow-[0_0_10px_#ff0033]"
              style={{ width: `${progress}%` }}
            />
          </div>

          <div className="flex items-center justify-between w-full mt-2 text-[10px] font-mono text-slate-400">
            <span>SYSTEM KERNEL: ACTIVE</span>
            <span className="text-red-400 font-semibold">{progress}% LOADED</span>
            <span>READY</span>
          </div>
        </div>
      </div>

      <div className="relative z-10 flex flex-col sm:flex-row items-center justify-between px-6 py-4 border-t border-[#1c202a]/80 bg-black/70 backdrop-blur-md text-[10px] font-mono text-slate-400 gap-2">
        <div className="flex items-center gap-2">
          <span className="crystal-icon-badge w-4 h-4 crystal-gem-ruby">
            <Activity className="h-2.5 w-2.5 text-red-400 crystal-icon-svg" />
          </span>
          <span>THREAT INTELLIGENCE • INCIDENT CORRELATION • RAPID RESPONSE</span>
        </div>
        <div className="hover:text-red-300 transition-colors">
          RESTRICTED SYSTEM // AUTHORIZED OPERATORS ONLY // CLICK ANYWHERE TO PROCEED
        </div>
      </div>
    </motion.div>
  );
};
