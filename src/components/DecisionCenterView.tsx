import React, { useState } from 'react';
import { useSoc } from '../context/SocContext';
import { useAuth } from '../context/AuthContext';
import { ThemeMode, Strategy } from '../types';

interface DecisionCenterViewProps {
  theme?: ThemeMode;
}

export const DecisionCenterView: React.FC<DecisionCenterViewProps> = ({ theme = 'dark' }) => {
  const {
    strategies,
    simulations,
    activeSimulation,
    isSimulating,
    runDecisionSimulation,
    activeIncident,
    queuePlaybookApproval,
  } = useSoc();
  const { canRunSimulations, canExecuteActions } = useAuth();
  const [cascadeDepth, setCascadeDepth] = useState<number>(3);
  const [decayFactor, setDecayFactor] = useState<number>(0.8);
  const [selectedStrategyId, setSelectedStrategyId] = useState<string>('STRAT-A-SURGICAL');

  const isLight = theme === 'light';

  const handleSimulate = () => {
    runDecisionSimulation({ cascade_depth: cascadeDepth, decay_factor: decayFactor });
  };

  const handleExecuteStrategy = (strat: Strategy) => {
    void queuePlaybookApproval(
      strat.actions,
      activeIncident?.id || '',
      strat.name,
      `Risk reduction: ${strat.risk_reduction}%. Estimated downtime: ${strat.downtime_hours} hrs. Cost: $${strat.operational_cost}`
    );
  };

  return (
    <div
      id="decision-center-view"
      className="w-full flex flex-col gap-5 p-4 lg:p-6 max-w-7xl mx-auto select-none"
    >
      {/* Top Banner */}
      <div
        className={`p-4 border rounded-lg flex flex-wrap items-center justify-between gap-4 transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]' : 'bg-[#050102] border-[#7f1d1d]/80 text-[#f3f4f6]'
        }`}
      >
        <div>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[22px] text-[#ef4444]">hub</span>
            <h2 className="font-['Space_Grotesk'] text-[18px] font-bold tracking-tight">
              Decision Center & Blast Radius Simulator
            </h2>
          </div>
          <p className="font-['JetBrains_Mono'] text-[11px] opacity-70 mt-0.5">
            EVALUATING ACTION STRATEGIES FOR INCIDENT: <strong className="text-[#ef4444]">{activeIncident?.id}</strong>
          </p>
        </div>

        {/* Simulation Controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 font-['JetBrains_Mono'] text-[11px]">
            <label className="opacity-70">DEPTH:</label>
            <select
              value={cascadeDepth}
              onChange={(e) => setCascadeDepth(Number(e.target.value))}
              className={`h-8 px-2 border rounded font-['JetBrains_Mono'] text-[11px] ${
                isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#000000] border-[#7f1d1d]/60 text-white'
              }`}
            >
              <option value="1">1 Hop (Local)</option>
              <option value="2">2 Hops (Direct Subnet)</option>
              <option value="3">3 Hops (Tier-1 Core)</option>
              <option value="5">5 Hops (Enterprise Wide)</option>
            </select>
          </div>

          <div className="flex items-center gap-2 font-['JetBrains_Mono'] text-[11px]">
            <label className="opacity-70">DECAY:</label>
            <select
              value={decayFactor}
              onChange={(e) => setDecayFactor(Number(e.target.value))}
              className={`h-8 px-2 border rounded font-['JetBrains_Mono'] text-[11px] ${
                isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#000000] border-[#7f1d1d]/60 text-white'
              }`}
            >
              <option value="0.9">0.90 (Low Decay)</option>
              <option value="0.8">0.80 (Standard)</option>
              <option value="0.6">0.60 (High Resistance)</option>
            </select>
          </div>

          <button
            type="button"
            disabled={isSimulating || !canRunSimulations}
            onClick={handleSimulate}
            className="h-8 px-4 border border-[#dc2626] bg-[#dc2626] hover:bg-[#b91c1c] disabled:opacity-50 text-white font-['JetBrains_Mono'] text-[11px] font-bold rounded flex items-center gap-1.5 transition-colors"
          >
            {isSimulating ? (
              <>
                <span className="material-symbols-outlined text-[14px] animate-spin">refresh</span>
                Simulating...
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-[14px]">model_training</span>
                Simulate Cascades
              </>
            )}
          </button>
        </div>
      </div>

      {/* Side-by-Side Comparison Matrix (Requirement 5) */}
      <div
        className={`border rounded-lg overflow-hidden transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
        }`}
      >
        <div
          className={`p-3.5 border-b flex items-center justify-between ${
            isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#0a0203] border-[#7f1d1d]/60'
          }`}
        >
          <span className="font-['Space_Grotesk'] text-[14px] font-bold flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-[#3b82f6]">compare</span>
            Multi-Strategy Blast Radius & Impact Comparison Matrix
          </span>
          <span className="font-['JetBrains_Mono'] text-[10px] text-[#3b82f6]">[QUANTITATIVE EVALUATION]</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px] font-['JetBrains_Mono'] divide-y divide-inherit">
            <thead>
              <tr className={isLight ? 'bg-[#f1f5f9] text-[#475569]' : 'bg-black/60 text-[#9ca3af]'}>
                <th className="p-3">STRATEGY / APPROACH</th>
                <th className="p-3">BLAST RADIUS (HOSTS)</th>
                <th className="p-3">BUSINESS DISRUPTION</th>
                <th className="p-3">CONTAINMENT PROB.</th>
                <th className="p-3">MTTR RECOVERY</th>
                <th className="p-3">OP COST ($)</th>
                <th className="p-3">APPROVAL GATE</th>
                <th className="p-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-inherit">
              {simulations.map((comp) => {
                const isBaseline = comp.id === 'COMP-BASELINE';
                return (
                  <tr
                    key={comp.id}
                    className={`hover:bg-black/10 transition-colors ${
                      isBaseline ? (isLight ? 'bg-[#fef2f2]' : 'bg-[#200508]') : ''
                    }`}
                  >
                    <td className="p-3 font-bold">
                      <div className="font-['Space_Grotesk'] text-[13px]">{comp.name}</div>
                      <div className="text-[10px] opacity-60 mt-0.5">{comp.actions.join(' • ')}</div>
                    </td>
                    <td className="p-3">
                      <span
                        className={`font-bold ${
                          comp.blastRadius > 100
                            ? 'text-[#ef4444]'
                            : comp.blastRadius > 10
                            ? 'text-[#f59e0b]'
                            : 'text-[#10b981]'
                        }`}
                      >
                        {comp.blastRadius} Hosts
                      </span>
                    </td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-2 rounded bg-black/30 overflow-hidden">
                          <div
                            className={`h-full ${
                              comp.businessDisruption > 50
                                ? 'bg-[#ef4444]'
                                : comp.businessDisruption > 20
                                ? 'bg-[#f59e0b]'
                                : 'bg-[#10b981]'
                            }`}
                            style={{ width: `${comp.businessDisruption}%` }}
                          />
                        </div>
                        <span className="font-bold">{comp.businessDisruption}%</span>
                      </div>
                    </td>
                    <td className="p-3">
                      <span
                        className={`font-bold ${
                          comp.containmentProbability > 85
                            ? 'text-[#10b981]'
                            : comp.containmentProbability > 50
                            ? 'text-[#f59e0b]'
                            : 'text-[#ef4444]'
                        }`}
                      >
                        {comp.containmentProbability}%
                      </span>
                    </td>
                    <td className="p-3">{comp.recoveryTimeHours}h</td>
                    <td className="p-3">${comp.operationalCost.toLocaleString()}</td>
                    <td className="p-3">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                          comp.requiresApproval
                            ? 'border-[#f59e0b] text-[#f59e0b] bg-[#f59e0b]/10'
                            : 'border-[#10b981] text-[#10b981] bg-[#10b981]/10'
                        }`}
                      >
                        {comp.requiresApproval ? 'REQUIRED' : 'PRE-APPROVED'}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      {!isBaseline && (
                        <button
                          type="button"
                          disabled={!canExecuteActions}
                          onClick={() => {
                            const strat = strategies.find((s) => s.id.includes(comp.id.replace('COMP-', ''))) || strategies[0];
                            handleExecuteStrategy(strat);
                          }}
                          className="px-3 py-1 border border-[#ef4444] text-[#ef4444] hover:bg-[#ef4444] hover:text-white rounded text-[10px] font-bold transition-colors"
                        >
                          Select & Authorize
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Strategies Detailed Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {strategies.map((strat) => (
          <div
            key={strat.id}
            onClick={() => setSelectedStrategyId(strat.id)}
            className={`border rounded-lg p-4 flex flex-col justify-between cursor-pointer transition-all ${
              selectedStrategyId === strat.id
                ? 'border-[#ef4444] shadow-[0_0_15px_rgba(239,68,68,0.3)]'
                : 'border-inherit opacity-85 hover:opacity-100'
            } ${isLight ? 'bg-[#ffffff]' : 'bg-[#050102]'}`}
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="font-['JetBrains_Mono'] text-[10px] text-[#ef4444] font-bold">
                  {strat.id}
                </span>
                <span
                  className={`px-2 py-0.5 border text-[9px] font-['JetBrains_Mono'] font-bold rounded ${
                    strat.approval_required
                      ? 'border-[#f59e0b] text-[#f59e0b] bg-[#f59e0b]/10'
                      : 'border-[#10b981] text-[#10b981] bg-[#10b981]/10'
                  }`}
                >
                  {strat.approval_required ? 'OPERATOR GATE' : 'AUTONOMOUS READY'}
                </span>
              </div>

              <h3 className="font-['Space_Grotesk'] text-[14px] font-bold">{strat.name}</h3>
              <p className="font-['Geist'] text-[12px] opacity-80 mt-1.5 leading-relaxed">
                {strat.description}
              </p>

              <div className="mt-3 flex flex-col gap-1 text-[11px] font-['JetBrains_Mono']">
                <span className="text-[10px] opacity-60 uppercase">Actions:</span>
                {strat.actions.map((act, i) => (
                  <div key={i} className="flex items-center gap-1.5 opacity-90">
                    <span className="w-1 h-1 rounded-full bg-[#ef4444]" />
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-inherit flex items-center justify-between">
              <div className="font-['JetBrains_Mono'] text-[10px]">
                <div>REDUCTION: <strong className="text-[#10b981]">{strat.risk_reduction}%</strong></div>
                <div>DOWNTIME: <strong>{strat.downtime_hours}h</strong></div>
              </div>

              <button
                type="button"
                disabled={!canExecuteActions}
                onClick={(e) => {
                  e.stopPropagation();
                  handleExecuteStrategy(strat);
                }}
                className="px-3 py-1.5 border border-[#ef4444] bg-[#ef4444]/15 hover:bg-[#ef4444] hover:text-white text-[#ef4444] rounded text-[11px] font-['JetBrains_Mono'] font-bold transition-all"
              >
                Execute
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Cascading Dependency Graph & Impact Breakdown */}
      {activeSimulation && (
        <div
          className={`border rounded-lg p-4 transition-colors ${
            isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
          }`}
        >
          <div className="flex items-center justify-between border-b border-inherit pb-3 mb-3">
            <span className="font-['Space_Grotesk'] text-[14px] font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-[18px] text-[#ef4444]">account_tree</span>
              Cascading Dependency Blast Propagation (Depth: {activeSimulation.cascade_depth} Hops)
            </span>
            <span className="font-['JetBrains_Mono'] text-[10px] text-[#10b981]">
              SIMULATION CONFIDENCE: {Math.round(activeSimulation.confidence_score * 100)}%
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-['JetBrains_Mono'] text-[11px]">
            {activeSimulation.cascading_affected_assets.map((casc, i) => (
              <div
                key={i}
                className={`p-3 border rounded ${
                  isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#0c0204] border-[#7f1d1d]/40'
                }`}
              >
                <div className="flex justify-between items-center text-[10px] mb-1">
                  <span className="font-bold text-[#ef4444]">HOP #{casc.hop_distance}</span>
                  <span className="text-[#f59e0b] font-bold">
                    IMPACT: {Math.round(casc.decayed_impact * 100)}%
                  </span>
                </div>
                <div className="font-bold text-[12px]">{casc.asset_id}</div>
                <div className="opacity-70 text-[10px] mt-1">{casc.reason}</div>
              </div>
            ))}
          </div>

          <div className="mt-3 pt-3 border-t border-inherit flex flex-wrap items-center justify-between gap-2 text-[11px] font-['JetBrains_Mono']">
            <span>AFFECTED DEPARTMENTS: <strong>{activeSimulation.affected_departments.join(', ')}</strong></span>
            <span>ESTIMATED DOWNTIME: <strong>{activeSimulation.estimated_downtime_hours} hrs</strong></span>
            <span>ESTIMATED RECOVERY: <strong>{activeSimulation.recovery_time_hours} hrs</strong></span>
          </div>
        </div>
      )}
    </div>
  );
};
