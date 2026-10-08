import React from 'react';
import { NavTab, ThemeMode, Alert, Incident, AffectedAsset, SecurityEvent } from '../types';
import { AutonomousVectorRadar } from './AutonomousVectorRadar';

interface TacticalModuleViewProps {
  tab: NavTab;
  onNavigateToLive: () => void;
  theme?: ThemeMode;
  alerts?: Alert[];
  incidents?: Incident[];
  assets?: AffectedAsset[];
  events?: SecurityEvent[];
}

export const TacticalModuleView: React.FC<TacticalModuleViewProps> = ({
  tab,
  onNavigateToLive,
  theme = 'dark',
  alerts = [], incidents = [], assets = [], events = [],
}) => {
  const meta: Record<string, { title: string; subtitle: string; icon: string; records: { k: string; v: string }[] }> = {
    alerts: {
      title: 'Alert Aggregation & Deduplication',
      subtitle: 'Backend alert records for the authenticated workspace.',
      icon: 'notifications_active',
      records: alerts.map(a => ({ k: `${a.title} [${a.severity}]`, v: `${a.status} • ${a.host} • ${a.timestamp} • Incident: ${a.incidentId || 'unlinked'}` })),
    },
    assets: {
      title: 'Enterprise Cyber Asset Inventory',
      subtitle: 'Affected assets returned by the backend incident inventory.',
      icon: 'devices',
      records: assets.map(a => ({ k: `${a.name} (${a.role})`, v: `${a.status} • ${a.os} • IP: ${a.ip}` })),
    },
    knowledge_graph: {
      title: 'Adversary & Entity Knowledge Graph',
      subtitle: 'Use the Knowledge Graph module for backend graph traversal and entity relationships.',
      icon: 'hub',
      records: incidents.flatMap(i => (i.affectedAssets || []).map(a => ({ k: a.name, v: `Incident ${i.id} • ${a.status} • ${a.criticality}` }))),
    },
    risk_intel: {
      title: 'Risk & Attack Surface Intelligence',
      subtitle: 'Risk values calculated by backend services.',
      icon: 'security',
      records: incidents.map(i => ({ k: i.id, v: `Risk: ${i.riskScore ?? 'N/A'} • Level: ${i.riskLevel ?? 'N/A'} • Severity: ${i.severity}` })),
    },
    predictions: {
      title: 'Predictive Adversary Next-Action Modeling',
      subtitle: 'Predictions returned by the backend prediction service.',
      icon: 'trending_up',
      records: incidents.flatMap(i => (i.predictions || []).flatMap(p => (p.next_affected_assets || []).map(a => ({ k: a.asset, v: `Confidence: ${(a.confidence * 100).toFixed(1)}% • ${a.reason}` })))),
    },
    mitigations: {
      title: 'Mitigation & Countermeasure Matrix',
      subtitle: 'Backend-reported recommended actions. Execution remains behind explicit approval.',
      icon: 'smart_toy',
      records: incidents.flatMap(i => (i.recommendedActions || []).map(a => ({ k: `${a.title} [${a.status}]`, v: `${a.target} • Incident ${i.id}` }))),
    },
    playbooks: {
      title: 'Playbook Engine (SOAR)',
      subtitle: 'Backend playbook state for the authenticated workspace.',
      icon: 'auto_mode',
      records: incidents.flatMap(i => (i.recommendedActions || []).filter(a => a.playbookId).map(a => ({ k: `${a.playbookId} • ${a.title}`, v: `${a.status} • ${a.target}` }))),
    },
    threat_intel: {
      title: 'Threat Intelligence',
      subtitle: 'Threat intelligence attached to persisted incident records.',
      icon: 'radar',
      records: incidents.flatMap(i => Object.entries(i.threatIntelligence || {}).map(([k, v]) => ({ k: `${i.id} • ${k}`, v: typeof v === 'string' ? v : JSON.stringify(v) }))),
    },
  };
  const current = meta[tab] || {
    title: `Module: ${tab.replace('_', ' ').toUpperCase()}`,
    subtitle: 'No backend records are available for this module.',
    icon: 'security',
    records: events.slice(0, 100).map(e => ({ k: e.id, v: `${e.severity} • ${e.eventType} • ${e.source}` })),
  };

  const isLight = theme === 'light';

  return (
    <div
      id={`module-screen-${tab}`}
      className={`fixed top-14 left-60 bottom-7 right-0 overflow-y-auto custom-scrollbar p-4 space-y-4 select-none transition-colors duration-200 ${
        isLight ? 'bg-[#f4f5f8] text-[#0f172a]' : 'bg-[#000000] text-[#e5e5e5]'
      }`}
    >
      <div className={`flex justify-between items-center pb-2 border-b transition-colors duration-200 ${
        isLight ? 'border-[#e2e8f0]' : 'border-[#7f1d1d]/60'
      }`}>
        <div>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[22px] text-[#ef4444]">
              {current.icon}
            </span>
            <h1 className={`font-['Space_Grotesk'] text-[24px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              {current.title}
            </h1>
          </div>
          <p className={`font-['Geist'] text-[12px] mt-0.5 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
            {current.subtitle}
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
          Back to Live Event Stream
        </button>
      </div>

      {tab === 'threat_intel' && (
        <div className="mb-4">
          <AutonomousVectorRadar
            theme={theme}
            isExpandedView={true}
            events={events}
          />
        </div>
      )}

      <div className="space-y-3">
        {current.records.map((rec, idx) => (
          <div
            key={idx}
            className={`p-3 border flex justify-between items-center font-['JetBrains_Mono'] text-[12px] transition-colors ${
              isLight
                ? 'border-[#e2e8f0] bg-[#ffffff] hover:border-[#dc2626] shadow-sm'
                : 'border-[#7f1d1d]/60 bg-[#050102] hover:border-[#ef4444] shadow-[0_0_10px_rgba(0,0,0,0.8)]'
            }`}
          >
            <div className={`font-semibold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
              {rec.k}
            </div>
            <div className={`text-[11px] font-medium ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
              {rec.v}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
