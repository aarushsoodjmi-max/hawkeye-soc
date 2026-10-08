import React, { useState } from 'react';
import { SecurityEvent, ThemeMode } from '../types';

interface EventContextDrawerProps {
  event: SecurityEvent | null;
  onClose: () => void;
  onViewIncident?: (incidentId: string) => void;
  onBlockIp: (ip: string) => void;
  onQuarantineHost: (host: string) => void;
  onCorrelateIncident: (eventId: string) => void;
  isPinned: boolean;
  onTogglePin: () => void;
  theme?: ThemeMode;
  placement?: 'bottom' | 'side';
  onTogglePlacement?: () => void;
}

export const EventContextDrawer: React.FC<EventContextDrawerProps> = ({
  event,
  onClose,
  onViewIncident,
  onBlockIp,
  onQuarantineHost,
  onCorrelateIncident,
  isPinned,
  onTogglePin,
  theme = 'dark',
  placement = 'bottom',
  onTogglePlacement,
}) => {
  const [copied, setCopied] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  if (!event) return null;

  const isLight = theme === 'light';

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(event.rawPayload, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleBlockClick = () => {
    onBlockIp(event.sourceIp);
    setActionNotice(`Tactical block applied to IP ${event.sourceIp}`);
    setTimeout(() => setActionNotice(null), 3000);
  };

  const handleQuarantineClick = () => {
    const host = event.sourceHost || event.sourceIp;
    onQuarantineHost(host);
    setActionNotice(`Endpoint isolation directive issued to ${host}`);
    setTimeout(() => setActionNotice(null), 3000);
  };

  const severityBadgeClass =
    event.severity === 'CRITICAL'
      ? isLight
        ? 'bg-[#fee2e2] border-[#dc2626] text-[#991b1b]'
        : 'bg-[#7f1d1d]/90 border-[#ef4444] text-[#ffffff] shadow-[0_0_6px_rgba(239,68,68,0.3)]'
      : event.severity === 'HIGH'
      ? isLight
        ? 'bg-[#fef2f2] border-[#fca5a5] text-[#b91c1c]'
        : 'bg-[#450a0a] border-[#dc2626] text-[#fca5a5]'
      : event.severity === 'MEDIUM'
      ? isLight
        ? 'bg-[#fef3c7] border-[#fcd34d] text-[#b45309]'
        : 'bg-[#160608] border-[#ef4444]/60 text-[#ff8080]'
      : isLight
      ? 'bg-[#f8fafc] border-[#cbd5e1] text-[#64748b]'
      : 'bg-[#000000] border-[#444444] text-[#9ca3af]';

  const renderMetadataCard = () => (
    <div className={`p-3 border space-y-2 transition-colors ${
      isLight ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm' : 'bg-[#050102] border-[#7f1d1d]/40'
    }`}>
      <div className={`flex justify-between items-center pb-2 border-b ${
        isLight ? 'border-[#e2e8f0]' : 'border-[#7f1d1d]/40'
      }`}>
        <span className={`font-['JetBrains_Mono'] text-[10px] uppercase tracking-wider font-semibold ${
          isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
        }`}>
          Event ID
        </span>
        <span className={`font-['JetBrains_Mono'] text-[12px] font-bold select-all ${
          isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'
        }`}>
          {event.id}
        </span>
      </div>

      <div className="space-y-1.5 pt-0.5 text-[11px] font-['JetBrains_Mono']">
        <div className="flex justify-between items-center">
          <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>TIMESTAMP</span>
          <span className={`font-medium ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
            {event.timestamp} UTC
          </span>
        </div>
        <div className="flex justify-between items-center">
          <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>PRINCIPAL</span>
          <span className={`font-medium ${isLight ? 'text-[#dc2626]' : 'text-[#ef4444]'}`}>
            {event.principal}
          </span>
        </div>
        <div className="flex justify-between items-center">
          <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>SOURCE / AGENT</span>
          <span className={isLight ? 'text-[#0f172a]' : 'text-[#e5e5e5]'}>
            {event.agentVersion || `${event.source} Agent`}
          </span>
        </div>
        <div className="flex justify-between items-center">
          <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>ENDPOINT HOST</span>
          <span className={isLight ? 'text-[#0f172a]' : 'text-[#e5e5e5]'}>
            {event.sourceHost || 'N/A'}
          </span>
        </div>
      </div>
    </div>
  );

  const renderSecurityContextCard = () => {
    if (!event.securityContext || event.securityContext.length === 0) return null;
    return (
      <div className={`p-3 border space-y-2.5 transition-colors ${
        isLight ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm' : 'bg-[#050102] border-[#7f1d1d]/40'
      }`}>
        <div className={`flex items-center gap-1.5 ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
          <span className="material-symbols-outlined text-[15px]">warning</span>
          <span className="font-['JetBrains_Mono'] text-[10px] font-bold tracking-wider uppercase">
            Parsed Security Context
          </span>
        </div>

        <div className="space-y-2">
          {event.securityContext.map((ctx, idx) => {
            if (ctx.type === 'mfa_bypass') {
              return (
                <div
                  key={idx}
                  className={`p-2.5 border-l-2 space-y-1 ${
                    isLight
                      ? 'bg-[#fee2e2]/60 border-[#dc2626] text-[#0f172a]'
                      : 'bg-[#180407] border-[#ef4444] text-[#e5e5e5]'
                  }`}
                >
                  <div className={`font-semibold font-['JetBrains_Mono'] text-[11px] ${
                    isLight ? 'text-[#991b1b]' : 'text-[#ff8080]'
                  }`}>
                    {ctx.title}
                  </div>
                  <div className={`text-[11px] leading-relaxed ${isLight ? 'text-[#475569]' : 'text-[#d1d5db]'}`}>
                    {ctx.description}
                  </div>
                  {ctx.details?.mitreId && (
                    <div className={`font-['JetBrains_Mono'] text-[10px] pt-0.5 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                      MITRE:{' '}
                      <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                        {ctx.details.mitreId}
                      </span>{' '}
                      ({ctx.details.mitreTactic})
                    </div>
                  )}
                </div>
              );
            }

            if (ctx.type === 'geoip_travel') {
              return (
                <div
                  key={idx}
                  className={`p-2.5 border-l-2 space-y-1 ${
                    isLight
                      ? 'bg-[#fef3c7]/60 border-[#d97706] text-[#0f172a]'
                      : 'bg-[#1c1400] border-[#ffd700] text-[#e5e5e5]'
                  }`}
                >
                  <div className={`font-semibold font-['JetBrains_Mono'] text-[11px] flex items-center gap-1.5 ${
                    isLight ? 'text-[#b45309]' : 'text-[#ffd700]'
                  }`}>
                    <span className="material-symbols-outlined text-[13px]">flight_takeoff</span>
                    {ctx.title}
                  </div>
                  <div className={`font-['JetBrains_Mono'] text-[11px] leading-relaxed ${isLight ? 'text-[#475569]' : 'text-[#d1d5db]'}`}>
                    {ctx.description}
                  </div>
                  {ctx.details?.speed && (
                    <div className={`text-[10px] font-['JetBrains_Mono'] font-semibold ${isLight ? 'text-[#b91c1c]' : 'text-[#ff3b38]'}`}>
                      Δ Velocity: {ctx.details.speed}
                    </div>
                  )}
                </div>
              );
            }

            return (
              <div
                key={idx}
                className={`p-2.5 border-l-2 ${
                  isLight
                    ? 'bg-[#f8fafc] border-[#dc2626] text-[#0f172a]'
                    : 'bg-[#0e0709] border-[#ef4444] text-[#e5e5e5]'
                }`}
              >
                <div className={`font-semibold font-['JetBrains_Mono'] text-[11px] ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                  {ctx.title}
                </div>
                <div className={`mt-0.5 text-[11px] leading-relaxed ${isLight ? 'text-[#475569]' : 'text-[#d1d5db]'}`}>
                  {ctx.description}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  const renderIncidentCard = () => (
    event.correlatedIncident ? (
      <div className={`p-3 border flex items-center justify-between transition-colors ${
        isLight ? 'bg-[#fee2e2]/50 border-[#dc2626]' : 'bg-[#160407] border-[#7f1d1d]'
      }`}>
        <div>
          <div className={`font-['JetBrains_Mono'] text-[9px] uppercase tracking-wider font-semibold ${
            isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
          }`}>
            Correlated Incident
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className={`font-['Space_Grotesk'] text-[13px] font-bold ${
              isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
            }`}>
              {event.correlatedIncident}
            </span>
            <span className={`px-1.5 py-0.2 border font-['JetBrains_Mono'] text-[9px] font-bold ${
              isLight
                ? 'bg-[#dc2626] text-[#ffffff] border-[#dc2626]'
                : 'bg-[#7f1d1d] border-[#ef4444] text-[#ffffff]'
            }`}>
              RISK {event.riskScore ?? 'N/A'}
            </span>
          </div>
        </div>

        {onViewIncident && (
          <button
            type="button"
            id="btn-view-correlated-incident"
            onClick={() => onViewIncident(event.correlatedIncident!)}
            className={`h-7 px-2.5 border font-['JetBrains_Mono'] text-[10px] font-bold flex items-center gap-1 transition-colors ${
              isLight
                ? 'border-[#dc2626] bg-[#fee2e2] text-[#b91c1c] hover:bg-[#dc2626] hover:text-[#ffffff]'
                : 'border-[#ef4444] bg-[#000000] text-[#ef4444] hover:bg-[#ef4444] hover:text-[#ffffff]'
            }`}
          >
            <span>VIEW CASE</span>
            <span className="material-symbols-outlined text-[12px]">arrow_forward</span>
          </button>
        )}
      </div>
    ) : (
      <div className={`p-3 border flex items-center justify-between transition-colors ${
        isLight ? 'bg-[#ffffff] border-[#e2e8f0]' : 'bg-[#030102] border-[#7f1d1d]/40'
      }`}>
        <div className={`font-['JetBrains_Mono'] text-[11px] ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
          Not linked to active incident
        </div>
        <button
          type="button"
          onClick={() => onCorrelateIncident(event.id)}
          className={`h-7 px-2.5 border font-['JetBrains_Mono'] text-[10px] font-medium transition-colors ${
            isLight
              ? 'border-[#dc2626] text-[#dc2626] bg-[#fee2e2]/40 hover:bg-[#dc2626] hover:text-[#ffffff]'
              : 'border-[#7f1d1d] hover:border-[#ef4444] text-[#ef4444] bg-[#000000]'
          }`}
        >
          + Link to Incident
        </button>
      </div>
    )
  );

  const renderRawPayloadCard = () => (
    <div className={`p-3 border space-y-2 flex-1 flex flex-col transition-colors ${
      isLight ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm' : 'bg-[#030102] border-[#7f1d1d]/40'
    }`}>
      <div className="flex justify-between items-center shrink-0">
        <span className={`font-['JetBrains_Mono'] text-[10px] font-bold uppercase tracking-wider ${
          isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
        }`}>
          RAW JSON PAYLOAD
        </span>
        <button
          type="button"
          id="btn-copy-raw-json"
          onClick={handleCopyJson}
          className={`h-6 px-2 border font-['JetBrains_Mono'] text-[10px] flex items-center gap-1 transition-colors ${
            isLight
              ? 'border-[#dc2626] text-[#b91c1c] bg-[#fee2e2] hover:bg-[#dc2626] hover:text-[#ffffff]'
              : 'border-[#ef4444]/60 hover:border-[#ef4444] text-[#ef4444] bg-[#000000]'
          }`}
        >
          <span className="material-symbols-outlined text-[12px]">
            {copied ? 'check' : 'content_copy'}
          </span>
          <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
        </button>
      </div>

      <pre className={`p-2.5 border font-['JetBrains_Mono'] text-[10.5px] leading-relaxed overflow-x-auto flex-1 max-h-52 custom-scrollbar select-text ${
        isLight
          ? 'bg-[#f8fafc] border-[#e2e8f0] text-[#0f172a]'
          : 'bg-[#000000] border-[#2d0a0d] text-[#ef4444]'
      }`}>
        {JSON.stringify(event.rawPayload, null, 2)}
      </pre>
    </div>
  );

  const renderTacticalActionsCard = () => (
    <div className={`p-3 border space-y-2.5 transition-colors ${
      isLight ? 'bg-[#ffffff] border-[#e2e8f0] shadow-sm' : 'bg-[#030102] border-[#7f1d1d]/40'
    }`}>
      <span className={`font-['JetBrains_Mono'] text-[10px] font-bold tracking-wider uppercase block ${
        isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
      }`}>
        Tactical Intervention
      </span>

      <div className="space-y-1.5">
        <button
          type="button"
          id="btn-action-block-ip"
          onClick={handleBlockClick}
          disabled={event.blocked}
          className={`w-full py-1.5 px-3 border font-['JetBrains_Mono'] text-[11px] font-semibold flex items-center justify-between transition-colors ${
            event.blocked
              ? 'bg-[#151515] border-[#333333] text-[#6b7280] cursor-not-allowed'
              : isLight
              ? 'bg-[#fee2e2] border-[#dc2626] text-[#991b1b] hover:bg-[#dc2626] hover:text-[#ffffff]'
              : 'bg-[#7f1d1d]/80 border-[#ef4444] text-[#ffffff] hover:bg-[#991b1b]'
          }`}
        >
          <span className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[14px]">block</span>
            {event.blocked ? 'IP Null-Routed' : `Block IP (${event.sourceIp})`}
          </span>
          <span className="text-[10px] uppercase font-bold">
            {event.blocked ? 'BLOCKED' : 'EXECUTE'}
          </span>
        </button>

        <button
          type="button"
          id="btn-action-quarantine-host"
          onClick={handleQuarantineClick}
          disabled={event.quarantined}
          className={`w-full py-1.5 px-3 border font-['JetBrains_Mono'] text-[11px] font-semibold flex items-center justify-between transition-colors ${
            event.quarantined
              ? 'bg-[#151515] border-[#333333] text-[#6b7280] cursor-not-allowed'
              : isLight
              ? 'bg-[#fef2f2] border-[#fca5a5] text-[#b91c1c] hover:bg-[#fca5a5] hover:text-[#0f172a]'
              : 'bg-[#2b080d] border-[#ef4444] text-[#fee2e2] hover:bg-[#450a0a]'
          }`}
        >
          <span className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[14px]">cell_wifi</span>
            {event.quarantined
              ? 'Host Isolated'
              : `Quarantine Host (${event.sourceHost || 'WS-FIN-04'})`}
          </span>
          <span className="text-[10px] uppercase font-bold">
            {event.quarantined ? 'ISOLATED' : 'EXECUTE'}
          </span>
        </button>

        {!event.correlatedIncident && (
          <button
            type="button"
            id="btn-action-correlate"
            onClick={() => onCorrelateIncident(event.id)}
            className={`w-full py-1.5 px-3 border font-['JetBrains_Mono'] text-[11px] font-medium flex items-center justify-between transition-colors ${
              isLight
                ? 'border-[#dc2626] text-[#b91c1c] hover:bg-[#fee2e2] bg-[#ffffff]'
                : 'border-[#7f1d1d] hover:border-[#ef4444] text-[#ff8080] hover:text-[#ffffff] bg-[#000000]'
            }`}
          >
            <span className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[14px]">merge_type</span>
              Correlate to Existing Case
            </span>
            <span className="text-[10px] uppercase">LINK</span>
          </button>
        )}
      </div>
    </div>
  );

  return (
    <aside
      id="event-context-drawer"
      className={`${
        placement === 'bottom'
          ? 'w-full h-80 border-t border-l-0 shrink-0'
          : 'w-[390px] border-l h-full shrink-0'
      } flex flex-col z-20 shadow-2xl select-none transition-all duration-200 ${
        isLight
          ? 'bg-[#f4f5f8] border-[#e2e8f0] text-[#0f172a]'
          : 'bg-[#000000] border-[#7f1d1d]/60 text-[#e5e5e5]'
      }`}
    >
      {/* Drawer Header */}
      <div className={`h-11 px-4 border-b flex items-center justify-between shrink-0 transition-colors duration-200 ${
        isLight
          ? 'bg-[#ffffff] border-[#e2e8f0]'
          : 'bg-[#060204] border-[#7f1d1d]/60'
      }`}>
        <div className="flex items-center gap-2.5">
          <span
            className={`w-2 h-2 rounded-full ${
              event.severity === 'CRITICAL'
                ? 'bg-[#ef4444] pulse-beacon shadow-[0_0_6px_#ef4444]'
                : event.severity === 'HIGH'
                ? 'bg-[#dc2626]'
                : 'bg-[#6b7280]'
            }`}
          />
          <span className={`font-['Space_Grotesk'] text-[14.5px] font-bold tracking-tight ${
            isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
          }`}>
            Event Context &amp; Threat Telemetry
          </span>
          <span
            className={`font-['JetBrains_Mono'] text-[10px] px-2 py-0.5 border font-semibold ${severityBadgeClass}`}
          >
            {event.severity}
          </span>
          <span className={`text-[11px] font-['JetBrains_Mono'] hidden sm:inline ${
            isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
          }`}>
            {event.eventType}
          </span>
        </div>
        <div className="flex items-center gap-1">
          {onTogglePlacement && (
            <button
              type="button"
              id="btn-drawer-placement"
              onClick={onTogglePlacement}
              className={`w-7 h-7 flex items-center justify-center rounded transition-colors ${
                isLight
                  ? 'text-[#64748b] hover:text-[#0f172a] hover:bg-[#f1f5f9]'
                  : 'text-[#9ca3af] hover:text-[#ffffff] hover:bg-[#1a080a]'
              }`}
              title={placement === 'bottom' ? 'Dock to Side Panel' : 'Dock to Bottom (Wider Table)'}
            >
              <span className="material-symbols-outlined text-[15px]">
                {placement === 'bottom' ? 'dock_to_right' : 'dock_to_bottom'}
              </span>
            </button>
          )}
          <button
            type="button"
            id="btn-drawer-pin"
            onClick={onTogglePin}
            className={`w-7 h-7 flex items-center justify-center rounded transition-colors ${
              isPinned
                ? isLight
                  ? 'text-[#b91c1c] bg-[#fee2e2] border border-[#dc2626]'
                  : 'text-[#ef4444] bg-[#2b080d] border border-[#ef4444]/50'
                : isLight
                ? 'text-[#64748b] hover:text-[#0f172a] hover:bg-[#f1f5f9]'
                : 'text-[#9ca3af] hover:text-[#ffffff] hover:bg-[#1a080a]'
            }`}
            title={isPinned ? 'Unpin Drawer' : 'Pin Drawer'}
          >
            <span
              className="material-symbols-outlined text-[15px]"
              style={{ fontVariationSettings: isPinned ? "'FILL' 1" : "'FILL' 0" }}
            >
              push_pin
            </span>
          </button>
          <button
            type="button"
            id="btn-drawer-close"
            onClick={onClose}
            className={`w-7 h-7 flex items-center justify-center rounded transition-colors ${
              isLight
                ? 'text-[#64748b] hover:text-[#dc2626] hover:bg-[#fee2e2]'
                : 'text-[#9ca3af] hover:text-[#ef4444] hover:bg-[#1a080a]'
            }`}
            title="Close Panel"
          >
            <span className="material-symbols-outlined text-[16px]">close</span>
          </button>
        </div>
      </div>

      {/* Action Notice Banner */}
      {actionNotice && (
        <div className="px-4 py-2 bg-[#dc2626] text-[#ffffff] font-['JetBrains_Mono'] text-[11px] border-b border-[#ef4444] flex items-center gap-2">
          <span className="material-symbols-outlined text-[14px]">bolt</span>
          <span>{actionNotice}</span>
        </div>
      )}

      {/* Drawer Body - Split into 3 columns if Bottom Dock, or Stacked if Side */}
      {placement === 'bottom' ? (
        <div className={`flex-1 overflow-y-auto custom-scrollbar p-3 grid grid-cols-1 md:grid-cols-3 gap-3 ${
          isLight ? 'bg-[#f4f5f8]' : 'bg-[#000000]'
        }`}>
          <div className="space-y-3">
            {renderMetadataCard()}
            {renderTacticalActionsCard()}
          </div>
          <div className="space-y-3">
            {renderSecurityContextCard()}
            {renderIncidentCard()}
          </div>
          <div className="flex flex-col h-full">
            {renderRawPayloadCard()}
          </div>
        </div>
      ) : (
        <div className={`flex-1 overflow-y-auto custom-scrollbar p-4 space-y-4 ${
          isLight ? 'bg-[#f4f5f8]' : 'bg-[#000000]'
        }`}>
          {renderMetadataCard()}
          {renderSecurityContextCard()}
          {renderIncidentCard()}
          {renderRawPayloadCard()}
          {renderTacticalActionsCard()}
        </div>
      )}
    </aside>
  );
};
