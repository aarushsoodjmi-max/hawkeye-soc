import React, { useState } from 'react';
import { ThemeMode, WorkspaceId, AiModelProvider } from '../types';
import { useAuth } from '../context/AuthContext';
import { useSoc } from '../context/SocContext';

interface TopHeaderProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onOpenQueryModal: () => void;
  onOpenContainmentModal: () => void;
  epsRate: number | null;
  latencyMs?: number | null;
  theme: ThemeMode;
  onToggleTheme: () => void;
  onReplaySplash?: () => void;
  onOpenLoginModal?: () => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  searchQuery,
  onSearchChange,
  onOpenQueryModal,
  onOpenContainmentModal,
  epsRate,
  latencyMs,
  theme,
  onToggleTheme,
  onReplaySplash,
  onOpenLoginModal,
}) => {
  const { workspace, setWorkspace, principal, role, isAuthenticated, logout } = useAuth();
  const {
    aiModelProvider,
    aiModelLabels,
    setAiModelProvider,
    backendStatus,
    loadScenario,
    scenarioRunning,
  } = useSoc();

  // Track the last stable status (connected / unavailable) so the pill shows
  // that instead of the transient 'checking' state during re-probes.
  const [lastStableStatus, setLastStableStatus] = useState<'connected' | 'unavailable'>('unavailable');
  React.useEffect(() => {
    if (backendStatus === 'connected' || backendStatus === 'unavailable') {
      setLastStableStatus(backendStatus);
    }
  }, [backendStatus]);
  const displayStatus = lastStableStatus;

  const [showConfigPopover, setShowConfigPopover] = useState(false);
  const isLight = theme === 'light';

  return (
    <header
      id="hawkeye-top-header"
      className={`fixed top-0 left-60 right-0 z-30 flex items-center justify-between px-4 h-14 border-b select-none overflow-hidden transition-colors duration-200 ${
        isLight
          ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm text-[#0f172a]'
          : 'bg-[#000000] border-[#7f1d1d]/60 shadow-[0_4px_30px_rgba(0,0,0,0.95)] text-[#f3f0f3]'
      }`}
    >
      {/* Cyber Grid Texture Overlay */}
      <div
        className={`absolute inset-0 pointer-events-none ${
          isLight ? 'cyber-grid-gold-overlay opacity-20' : 'cyber-grid-overlay opacity-30'
        }`}
      />

      {/* Dynamic Red Laser Scanner Line */}
      <div className="absolute bottom-0 left-0 right-0 h-[2px] overflow-hidden pointer-events-none">
        <div className="w-1/3 h-full bg-gradient-to-r from-transparent via-[#ef4444] to-transparent laser-scanner-line shadow-[0_0_10px_#ef4444]" />
      </div>

      {/* Left: Brand Title, Search, and Live Telemetry Ticker */}
      <div className="relative z-10 flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span
            className={`font-['Space_Grotesk'] text-[15px] font-bold tracking-wide whitespace-nowrap flex items-center gap-1.5 ${
              isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
            }`}
          >
            <span className="inline-block w-2 h-2 rounded-full bg-[#ef4444] pulse-beacon shadow-[0_0_8px_#ef4444]" />
            HAWKEYE SOC
          </span>

          {/* Backend Status Pill */}
          <span
            className={`px-1.5 py-0.5 font-['JetBrains_Mono'] text-[9px] font-bold uppercase rounded border ${
              displayStatus === 'connected'
                ? 'bg-[#10b981]/20 border-[#10b981] text-[#10b981]'
                : 'bg-[#f59e0b]/20 border-[#f59e0b] text-[#f59e0b]'
            }`}
            title={`Backend Status: ${backendStatus}`}
          >
            {displayStatus === 'connected' ? 'LIVE BACKEND' : 'BACKEND UNAVAILABLE'}
          </span>
        </div>

        {/* Workspace Selector Dropdown */}
        <div className="hidden md:flex items-center gap-1 font-['JetBrains_Mono'] text-[11px]">
          <span className="opacity-50 text-[10px]">WS:</span>
          <select
            id="header-workspace-select"
            value={workspace}
            onChange={(e) => setWorkspace(e.target.value as WorkspaceId)}
            className={`h-7 px-2 border rounded text-[10px] font-bold ${
              isLight
                ? 'bg-[#f8fafc] border-[#cbd5e1] text-[#0f172a]'
                : 'bg-[#050102] border-[#7f1d1d]/60 text-white'
            }`}
          >
            <option value="default">default (Enterprise Primary)</option>
            <option value="finance-sec">finance-sec (PCI-DSS)</option>
            <option value="cloud-infra">cloud-infra (AWS / Kube)</option>
            <option value="secops-core">secops-core (Air-Gapped)</option>
          </select>
        </div>

        {/* Search Input — vertically centered with consistent height across
            responsive widths; icon, field and reset button share one baseline. */}
        <div className="relative flex items-center h-7 w-48 lg:w-60">
          <span className="material-symbols-outlined absolute left-2 top-1/2 -translate-y-1/2 pointer-events-none text-[#ef4444] text-[15px]">
            search
          </span>
          <input
            id="global-telemetry-search"
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search host, IOC, IP..."
            className={`h-full w-full pl-7 pr-6 border rounded font-['JetBrains_Mono'] text-[11px] transition-all focus:outline-none ${
              isLight
                ? 'bg-[#f8fafc] border-[#cbd5e1] text-[#0f172a] focus:border-[#dc2626]'
                : 'bg-[#050102] border-[#7f1d1d]/60 text-[#ffffff] focus:border-[#ef4444]'
            }`}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => onSearchChange('')}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 flex items-center justify-center text-[#ef4444]"
            >
              <span className="material-symbols-outlined text-[13px]">close</span>
            </button>
          )}
        </div>
      </div>

      {/* Right Controls: AI Provider, 1-Click Scenario, Query, Containment, User */}
      <div className="relative z-10 flex items-center gap-2">
        {/* AI MODEL SELECTOR (SESSION-SCOPED) */}
        <div className="flex items-center gap-1 font-['JetBrains_Mono'] text-[11px] border border-inherit px-2 py-0.5 rounded bg-black/10">
          <span className="material-symbols-outlined text-[14px] text-[#ef4444]">smart_toy</span>
          <span className="opacity-60 text-[10px] hidden sm:inline">AI:</span>
          <select
            id="header-ai-model-provider-select"
            value={aiModelProvider}
            onChange={(e) => setAiModelProvider(e.target.value as AiModelProvider)}
            className={`h-6 px-1 border-0 bg-transparent text-[10px] font-bold cursor-pointer focus:outline-none ${
              aiModelProvider === 'gemini' ? 'text-[#3b82f6]' : aiModelProvider === 'demo' ? 'text-[#f59e0b]' : 'text-[#10b981]'
            }`}
            title="Session-Scoped AI Investigation Engine"
          >
            <option value="gemini" className="bg-[#000000] text-[#3b82f6]">
              {aiModelLabels.gemini}
            </option>
            <option value="local" className="bg-[#000000] text-[#10b981]">
              {aiModelLabels.local}
            </option>
            {import.meta.env.VITE_DEMO_MODE === 'true' && (
              <option value="demo" className="bg-[#000000] text-[#f59e0b]">
                {aiModelLabels.demo}
              </option>
            )}
          </select>
        </div>

        {/* 1-CLICK ATTACK SCENARIO BUTTON */}
        <button
          type="button"
          id="btn-trigger-attack-scenario"
          disabled={scenarioRunning}
          onClick={() => loadScenario('ransomware')}
          className="h-7 px-2.5 border border-[#ef4444] bg-[#ef4444]/15 hover:bg-[#ef4444] text-[#ef4444] hover:text-white rounded font-['JetBrains_Mono'] text-[10px] font-bold flex items-center gap-1 transition-all shadow-[0_0_10px_rgba(239,68,68,0.25)]"
          title="Inject Real-World Multi-Stage APT Attack Scenario"
        >
          <span className="material-symbols-outlined text-[14px]">
            {scenarioRunning ? 'sync' : 'bolt'}
          </span>
          <span className="hidden sm:inline">
            {scenarioRunning ? 'INJECTING...' : 'BACKEND SCENARIO'}
          </span>
        </button>

        {/* Run Query */}
        <button
          type="button"
          id="btn-run-query"
          onClick={onOpenQueryModal}
          className={`h-7 px-2.5 border rounded font-['JetBrains_Mono'] text-[10px] font-bold flex items-center gap-1 transition-all ${
            isLight
              ? 'bg-[#ffffff] border-[#dc2626] text-[#dc2626] hover:bg-[#fee2e2]'
              : 'bg-[#000000] border-[#ef4444] text-[#ef4444] hover:bg-[#ef4444]/20'
          }`}
        >
          <span className="material-symbols-outlined text-[13px]">terminal</span>
          <span className="hidden md:inline">KQL</span>
        </button>

        {/* Containment Button */}
        <button
          type="button"
          id="btn-deploy-containment"
          onClick={onOpenContainmentModal}
          className="h-7 px-2.5 font-['JetBrains_Mono'] text-[10px] font-bold rounded flex items-center gap-1 tracking-wider border border-[#ef4444] bg-[#dc2626] hover:bg-[#b91c1c] text-white shadow-[0_0_12px_rgba(220,38,38,0.4)]"
        >
          <span className="material-symbols-outlined text-[13px]">lock</span>
          <span className="hidden sm:inline uppercase">CONTAIN</span>
        </button>

        {/* Theme Toggle */}
        <button
          type="button"
          id="btn-toggle-theme"
          onClick={onToggleTheme}
          className={`w-7 h-7 flex items-center justify-center border rounded transition-colors text-[13px] ${
            isLight
              ? 'bg-[#f1f5f9] text-[#0f172a] border-[#cbd5e1]'
              : 'bg-[#000000] text-[#f3f4f6] border-[#7f1d1d]/70 hover:border-[#ef4444]'
          }`}
          title={isLight ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
        >
          <span className="material-symbols-outlined text-[15px] text-[#ef4444]">
            {isLight ? 'dark_mode' : 'light_mode'}
          </span>
        </button>

        {/* User Role Badge & Login Modal Button */}
        <button
          type="button"
          id="btn-open-rbac-modal"
          onClick={onOpenLoginModal}
          className={`h-7 px-2 border rounded font-['JetBrains_Mono'] text-[10px] font-bold flex items-center gap-1 transition-all ${
            isAuthenticated
              ? 'border-[#ef4444] bg-[#ef4444]/20 text-[#ef4444]'
              : 'border-[#64748b] bg-black/40 text-current'
          }`}
          title="Click to switch RBAC Role or Login"
        >
          <span className="material-symbols-outlined text-[13px]">badge</span>
          <span className="uppercase">{role}</span>
        </button>
      </div>
    </header>
  );
};
