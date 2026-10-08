import React from 'react';
import { NavTab, ThemeMode } from '../types';
import { HawkEyeLogo } from './HawkEyeLogo';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  incidentCount: number;
  containmentActive: boolean;
  onToggleContainmentModal: () => void;
  theme?: ThemeMode;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
  onReplaySplash?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  incidentCount,
  containmentActive,
  onToggleContainmentModal,
  theme = 'dark',
  isCollapsed = false,
  onToggleCollapse,
  onReplaySplash,
}) => {
  const isLight = theme === 'light';

  const primaryNavItems: { id: NavTab; label: string; icon: string; badge?: number }[] = [
    { id: 'overview', label: 'Overview', icon: 'dashboard' },
    { id: 'live_events', label: 'Live Events', icon: 'stream' },
    { id: 'incidents', label: 'Incidents', icon: 'warning', badge: incidentCount },
    { id: 'alerts', label: 'Alerts', icon: 'notifications_active' },
    { id: 'assets', label: 'Assets', icon: 'devices' },
  ];

  const intelNavItems: { id: NavTab; label: string; icon: string }[] = [
    { id: 'decision_center', label: 'Decision Center & Sim', icon: 'psychology' },
    { id: 'playbooks', label: 'SOAR Playbooks', icon: 'auto_mode' },
    { id: 'knowledge_graph', label: 'Knowledge Graph', icon: 'hub' },
    { id: 'risk_intel', label: 'Risk Intelligence', icon: 'security' },
    { id: 'predictions', label: 'Predictions', icon: 'insights' },
    { id: 'reports', label: 'Forensic Reports', icon: 'description' },
    { id: 'threat_intel', label: 'Threat Intelligence', icon: 'radar' },
    { id: 'simulator', label: 'Simulator Sandbox', icon: 'science' },
  ];

  return (
    <aside
      id="hawkeye-sidebar"
      className={`fixed left-0 top-0 bottom-0 z-40 flex flex-col border-r select-none transition-all duration-300 ${
        isCollapsed ? 'w-16' : 'w-60'
      } ${
        isLight
          ? 'bg-[#ffffff] border-[#e2e8f0] text-[#0f172a]'
          : 'bg-[#000000] border-[#7f1d1d]/50 text-[#f3f0f3]'
      }`}
    >
      {/* Header Brand Glyph, Title & Collapse Toggle */}
      <div
        id="hawkeye-brand-header"
        className={`h-14 flex items-center px-3 border-b transition-colors duration-200 ${
          isCollapsed ? 'justify-center' : 'justify-between'
        } ${
          isLight
            ? 'bg-[#ffffff] border-[#e2e8f0]'
            : 'bg-[#000000] border-[#7f1d1d]/60'
        }`}
      >
        <div className="flex items-center gap-2.5 overflow-hidden">
          <div
            className={`w-8 h-8 rounded shrink-0 flex items-center justify-center border overflow-hidden cursor-pointer transition-colors ${
              isLight
                ? 'bg-[#fee2e2] border-[#fca5a5] shadow-sm'
                : 'bg-[#000000] border-[#ef4444]/70 shadow-[0_0_8px_rgba(239,68,68,0.35)]'
            }`}
            title="HawkEye SOC (Click to replay Splash Screen)"
            onClick={onReplaySplash}
          >
            <HawkEyeLogo variant="badge" animated={false} showText={false} className="w-full h-full p-0.5" />
          </div>
          {!isCollapsed && (
            <div
              className="flex flex-col truncate cursor-pointer select-none"
              onClick={onReplaySplash}
              title="Click to replay Splash Screen"
            >
              <span className={`font-['Space_Grotesk'] text-[16px] font-bold tracking-tight leading-none ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                HAWKEYE
              </span>
              <span className={`font-['JetBrains_Mono'] text-[8.5px] mt-1 leading-none tracking-widest uppercase font-semibold ${isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'}`}>
                Autonomous SOC
              </span>
            </div>
          )}
        </div>

        {onToggleCollapse && (
          <button
            type="button"
            onClick={onToggleCollapse}
            id="btn-toggle-sidebar"
            className={`w-7 h-7 flex items-center justify-center rounded border transition-colors ${
              isLight
                ? 'border-[#cbd5e1] text-[#dc2626] hover:bg-[#fee2e2] hover:border-[#dc2626]'
                : 'border-[#7f1d1d]/60 text-[#ef4444] hover:text-[#ffffff] hover:bg-[#1f0509] hover:border-[#ef4444]'
            }`}
            title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            <span className="material-symbols-outlined text-[16px]">
              {isCollapsed ? 'keyboard_double_arrow_right' : 'keyboard_double_arrow_left'}
            </span>
          </button>
        )}
      </div>

      {/* Main Navigation List with grouped sections */}
      <nav id="hawkeye-navigation" className={`flex-1 overflow-y-auto custom-scrollbar px-2 py-3 space-y-4 ${isLight ? 'bg-[#ffffff]' : 'bg-[#000000]'}`}>
        {/* Core Operations Group */}
        <div>
          {!isCollapsed && (
            <div className={`px-3 pb-1.5 font-['JetBrains_Mono'] text-[9px] uppercase tracking-wider font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
              Operations
            </div>
          )}
          <ul className="space-y-0.5">
            {primaryNavItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <li key={item.id}>
                  <button
                    type="button"
                    id={`nav-item-${item.id}`}
                    onClick={() => onSelectTab(item.id)}
                    title={isCollapsed ? item.label : undefined}
                    className={`w-full rounded-sm flex items-center transition-colors group ${
                      isCollapsed ? 'justify-center p-2 relative' : 'px-2.5 py-1.5 gap-2.5 text-left'
                    } ${
                      isActive
                        ? isLight
                          ? 'text-[#991b1b] bg-[#fee2e2] border-l-2 border-[#dc2626] font-semibold'
                          : 'text-[#ffffff] bg-[#1a0507] border-l-2 border-[#ef4444] font-semibold shadow-[inset_0_0_12px_rgba(239,68,68,0.2)]'
                        : isLight
                          ? 'text-[#475569] hover:text-[#0f172a] hover:bg-[#f1f5f9]'
                          : 'text-[#9ca3af] hover:text-[#ffffff] hover:bg-[#0d0204]'
                    }`}
                  >
                    <div
                      className={`w-7 h-7 rounded flex items-center justify-center shrink-0 transition-colors ${
                        isActive
                          ? isLight
                            ? 'bg-[#fecaca] border border-[#dc2626] text-[#dc2626]'
                            : 'bg-[#2b070b] border border-[#ef4444] text-[#ef4444]'
                          : isLight
                            ? 'bg-[#f1f5f9] border border-[#e2e8f0] text-[#64748b] group-hover:border-[#cbd5e1] group-hover:text-[#0f172a]'
                            : 'bg-[#000000] border border-[#450a0a] text-[#9ca3af] group-hover:border-[#7f1d1d] group-hover:text-[#ffffff]'
                      }`}
                    >
                      <span
                        className="material-symbols-outlined text-[16px]"
                        style={{
                          fontVariationSettings: isActive ? "'FILL' 1" : "'FILL' 0",
                        }}
                      >
                        {item.icon}
                      </span>
                    </div>
                    {!isCollapsed && (
                      <span className={`text-[12px] truncate ${isActive ? (isLight ? 'font-bold text-[#0f172a]' : 'font-bold text-[#ffffff]') : ''}`}>
                        {item.label}
                      </span>
                    )}

                    {item.id === 'live_events' && (
                      <span
                        className={`${
                          isCollapsed
                            ? 'absolute top-1.5 right-1.5'
                            : 'ml-auto'
                        } w-1.5 h-1.5 rounded-full bg-[#ef4444] pulse-beacon shadow-[0_0_8px_#ef4444]`}
                      />
                    )}

                    {item.badge !== undefined && item.badge > 0 && (
                      <span
                        className={`${
                          isCollapsed
                            ? 'absolute top-1 right-1 text-[8.5px] px-1 py-0'
                            : 'ml-auto text-[10px] px-1.5 py-0.2'
                        } font-['JetBrains_Mono'] rounded font-bold ${
                          isLight
                            ? 'bg-[#fee2e2] text-[#991b1b] border border-[#fca5a5]'
                            : 'bg-[#7f1d1d] text-[#ffffff] border border-[#ef4444]/70 shadow-[0_0_6px_rgba(239,68,68,0.4)]'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>

        {/* Intelligence & Automation Group */}
        <div>
          {!isCollapsed && (
            <div className={`px-3 pb-1.5 font-['JetBrains_Mono'] text-[9px] uppercase tracking-wider font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'}`}>
              Intelligence
            </div>
          )}
          <ul className="space-y-0.5">
            {intelNavItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <li key={item.id}>
                  <button
                    type="button"
                    id={`nav-item-${item.id}`}
                    onClick={() => onSelectTab(item.id)}
                    title={isCollapsed ? item.label : undefined}
                    className={`w-full rounded-sm flex items-center transition-colors group ${
                      isCollapsed ? 'justify-center p-2 relative' : 'px-2.5 py-1.5 gap-2.5 text-left'
                    } ${
                      isActive
                        ? isLight
                          ? 'text-[#991b1b] bg-[#fee2e2] border-l-2 border-[#dc2626] font-semibold'
                          : 'text-[#ffffff] bg-[#1a0507] border-l-2 border-[#ef4444] font-semibold shadow-[inset_0_0_12px_rgba(239,68,68,0.2)]'
                        : isLight
                          ? 'text-[#475569] hover:text-[#0f172a] hover:bg-[#f1f5f9]'
                          : 'text-[#9ca3af] hover:text-[#ffffff] hover:bg-[#0d0204]'
                    }`}
                  >
                    <div
                      className={`w-7 h-7 rounded flex items-center justify-center shrink-0 transition-colors ${
                        isActive
                          ? isLight
                            ? 'bg-[#fecaca] border border-[#dc2626] text-[#dc2626]'
                            : 'bg-[#2b070b] border border-[#ef4444] text-[#ef4444]'
                          : isLight
                            ? 'bg-[#f1f5f9] border border-[#e2e8f0] text-[#64748b] group-hover:border-[#cbd5e1] group-hover:text-[#0f172a]'
                            : 'bg-[#000000] border border-[#450a0a] text-[#9ca3af] group-hover:border-[#7f1d1d] group-hover:text-[#ffffff]'
                      }`}
                    >
                      <span
                        className="material-symbols-outlined text-[16px]"
                        style={{
                          fontVariationSettings: isActive ? "'FILL' 1" : "'FILL' 0",
                        }}
                      >
                        {item.icon}
                      </span>
                    </div>
                    {!isCollapsed && (
                      <span className={`text-[12px] truncate ${isActive ? (isLight ? 'font-bold text-[#0f172a]' : 'font-bold text-[#ffffff]') : ''}`}>
                        {item.label}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      </nav>

      {/* Footer System Status & Containment Trigger */}
      <div className={`p-2.5 border-t space-y-2.5 ${isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]/50'}`}>
        <button
          type="button"
          id="sidebar-containment-mode-btn"
          onClick={onToggleContainmentModal}
          title={isCollapsed ? (containmentActive ? 'Containment Engaged' : 'Containment Mode') : undefined}
          className={`border transition-all font-['JetBrains_Mono'] font-bold tracking-wider ${
            isCollapsed
              ? 'w-10 h-10 flex items-center justify-center rounded-sm'
              : 'w-full py-2 px-3 flex items-center justify-center gap-2 text-[11px]'
          } ${
            containmentActive
              ? isLight
                ? 'bg-[#dc2626] text-[#ffffff] border-[#b91c1c]'
                : 'bg-[#dc2626] text-[#ffffff] border-[#ef4444] shadow-[0_0_16px_rgba(220,38,38,0.6)]'
              : isLight
                ? 'bg-[#ffffff] border-[#fca5a5] text-[#b91c1c] hover:bg-[#fee2e2]'
                : 'bg-[#000000] border-[#ef4444]/60 text-[#ff8080] hover:bg-[#7f1d1d] hover:text-[#ffffff] hover:border-[#ef4444]'
          }`}
        >
          <span className="material-symbols-outlined text-[16px]">security</span>
          {!isCollapsed && (containmentActive ? 'CONTAINMENT ENGAGED' : 'CONTAINMENT MODE')}
        </button>

        {!isCollapsed ? (
          <div className={`flex items-center justify-between text-[11px] font-['JetBrains_Mono'] px-1 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-[#ef4444] pulse-beacon shadow-[0_0_6px_#ef4444]" />
              <span className={`font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                MESH LIVE
              </span>
            </div>
            <span className={isLight ? 'text-[#94a3b8]' : 'text-[#9ca3af]'}>v4.19</span>
          </div>
        ) : (
          <div
            className="w-2 h-2 rounded-full bg-[#ef4444] pulse-beacon mx-auto"
            title="Sensor Mesh: backend state"
          />
        )}
      </div>
    </aside>
  );
};
