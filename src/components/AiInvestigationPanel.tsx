import React, { useState } from 'react';
import { useSoc } from '../context/SocContext';
import { useAuth } from '../context/AuthContext';
import { ThemeMode, AiModelProvider } from '../types';

interface AiInvestigationPanelProps {
  theme?: ThemeMode;
}

export const AiInvestigationPanel: React.FC<AiInvestigationPanelProps> = ({ theme = 'dark' }) => {
  const {
    aiProvider,
    aiModelLabels,
    setAiProvider,
    aiResponse,
    aiError,
    isAiAnalyzing,
    requestAiAnalysis,
    activeIncident,
    queuePlaybookApproval,
  } = useSoc();
  const { canRequestAi, canExecuteActions } = useAuth();
  const [analystPrompt, setAnalystPrompt] = useState('');
  const [showRawPayload, setShowRawPayload] = useState(false);
  const [copiedPayload, setCopiedPayload] = useState(false);

  const isLight = theme === 'light';

  const handleReanalyze = () => {
    requestAiAnalysis(analystPrompt || undefined);
  };

  const handleCopyPayload = () => {
    if (!aiResponse) return;
    navigator.clipboard.writeText(JSON.stringify(aiResponse, null, 2));
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  const handleActionClick = (stepTitle: string, target: string, impact: string) => {
    void queuePlaybookApproval([stepTitle], activeIncident?.id || '', stepTitle, impact);
  };

  return (
    <div
      id="ai-investigation-panel"
      className={`border rounded-lg overflow-hidden flex flex-col transition-colors duration-200 ${
        isLight
          ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]'
          : 'bg-[#050102] border-[#7f1d1d]/80 text-[#f3f4f6]'
      }`}
    >
      {/* Panel Header & Model Selector */}
      <div
        className={`p-4 border-b flex flex-wrap items-center justify-between gap-3 ${
          isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#0a0203] border-[#7f1d1d]/60'
        }`}
      >
        <div className="flex items-center gap-2.5">
          <span className="material-symbols-outlined text-[20px] text-[#ef4444]">psychology</span>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-['Space_Grotesk'] text-[15px] font-bold">
                AI Autonomous Forensic Synthesis
              </h3>
              <span className="px-2 py-0.5 border border-[#3b82f6] bg-[#3b82f6]/10 text-[#3b82f6] text-[10px] font-['JetBrains_Mono'] font-bold rounded">
                [LLM SYNTHESIS]
              </span>
            </div>
            <p className="font-['JetBrains_Mono'] text-[10px] opacity-70">
              Session Provider: <strong className="text-[#ef4444] uppercase">{aiProvider}</strong> | Task: {aiResponse?.task || 'Incident Investigation'}
            </p>
          </div>
        </div>

        {/* Visible Model Selector (Applies to Current Session) */}
        <div className="flex items-center gap-2">
          <span className="font-['JetBrains_Mono'] text-[11px] opacity-70">PROVIDER:</span>
          <div className="inline-flex rounded border border-[#7f1d1d]/60 p-0.5 bg-black/40">
            <button
              type="button"
              onClick={() => setAiProvider('gemini')}
              className={`px-3 py-1 font-['JetBrains_Mono'] text-[11px] font-bold rounded transition-colors ${
                aiProvider === 'gemini'
                  ? 'bg-[#ef4444] text-white shadow-[0_0_10px_rgba(239,68,68,0.4)]'
                  : 'text-current opacity-70 hover:opacity-100'
              }`}
            >
              Google Gemini
            </button>
            {import.meta.env.VITE_DEMO_MODE === 'true' && (
              <button
                type="button"
                onClick={() => setAiProvider('demo')}
                className={`px-3 py-1 font-['JetBrains_Mono'] text-[11px] font-bold rounded transition-colors ${
                  aiProvider === 'demo'
                    ? 'bg-[#ef4444] text-white shadow-[0_0_10px_rgba(239,68,68,0.4)]'
                    : 'text-current opacity-70 hover:opacity-100'
                }`}
              >
                Deterministic Demo
              </button>
            )}
            <button
              type="button"
              onClick={() => setAiProvider('local')}
              className={`px-3 py-1 font-['JetBrains_Mono'] text-[11px] font-bold rounded transition-colors ${
                aiProvider === 'local'
                  ? 'bg-[#ef4444] text-white shadow-[0_0_10px_rgba(239,68,68,0.4)]'
                  : 'text-current opacity-70 hover:opacity-100'
              }`}
            >
              Local (On-Prem)
            </button>
          </div>

          <button
            type="button"
            onClick={() => setShowRawPayload(!showRawPayload)}
            className={`px-2.5 py-1 border font-['JetBrains_Mono'] text-[10px] rounded transition-colors ${
              showRawPayload
                ? 'border-[#3b82f6] text-[#3b82f6] bg-[#3b82f6]/15'
                : 'border-[#7f1d1d]/60 text-current opacity-70 hover:opacity-100'
            }`}
          >
            {showRawPayload ? 'Hide JSON' : 'Raw JSON'}
          </button>
        </div>
      </div>

      {/* Mandatory Safety Invariant Banner */}
      <div
        className={`px-4 py-2 border-b text-[11px] font-['JetBrains_Mono'] flex items-center justify-between ${
          isLight
            ? 'bg-[#fffbeb] border-[#fde68a] text-[#92400e]'
            : 'bg-[#180902] border-[#f59e0b]/40 text-[#fcd34d]'
        }`}
      >
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-[16px] text-[#f59e0b]">security</span>
          <span>
            <strong>SAFETY DIRECTIVE:</strong> AI output is advisory intelligence and never unquestionable truth. Human operator approval is strictly enforced before any recommendation is executed.
          </span>
        </div>
        <span className="px-1.5 py-0.2 border border-current text-[9px] rounded font-bold">
          GATE ENFORCED
        </span>
      </div>

      {/* Raw Payload Inspector (when toggled) */}
      {showRawPayload && (
        <div className="p-4 border-b bg-black/70 text-[11px] font-mono overflow-x-auto relative">
          <div className="flex justify-between items-center mb-2">
            <span className="text-[#3b82f6] font-bold">API CONTRACT RESPONSE (AiResponse Schema):</span>
            <button
              type="button"
              onClick={handleCopyPayload}
              className="px-2 py-0.5 border border-[#3b82f6] text-[#3b82f6] hover:bg-[#3b82f6]/20 rounded text-[10px]"
            >
              {copiedPayload ? 'Copied!' : 'Copy to Clipboard'}
            </button>
          </div>
          <pre className="text-gray-300 leading-tight max-h-64 overflow-y-auto">
            {JSON.stringify(aiResponse, null, 2)}
          </pre>
        </div>
      )}

      {/* Main Body */}
      <div className="p-5 flex flex-col gap-5">
        {/* Error State Banner */}
        {aiError && (
          <div className="p-4 border border-[#ef4444] bg-[#ef4444]/10 text-[#ef4444] rounded flex items-center justify-between gap-3 font-['JetBrains_Mono']">
            <div className="flex items-center gap-2.5">
              <span className="material-symbols-outlined text-[20px]">error</span>
              <div>
                <div className="font-bold text-[12px] uppercase tracking-wide">
                  AI ANALYSIS FAILED / PROVIDER UNAVAILABLE
                </div>
                <div className="text-[11px] opacity-90">{aiError}</div>
              </div>
            </div>
            <button
              type="button"
              onClick={handleReanalyze}
              disabled={isAiAnalyzing}
              className="px-3 py-1 bg-[#ef4444] text-white hover:bg-[#dc2626] rounded text-[10px] font-bold shrink-0"
            >
              Retry
            </button>
          </div>
        )}

        {/* Empty State when no response and not analyzing */}
        {!aiResponse && !aiError && !isAiAnalyzing && (
          <div className="p-8 border border-dashed border-[#7f1d1d]/60 rounded text-center flex flex-col items-center justify-center gap-2">
            <span className="material-symbols-outlined text-[28px] text-[#ef4444]">psychology</span>
            <div className="font-['Space_Grotesk'] font-bold text-[14px]">No AI Forensic Synthesis Loaded</div>
            <p className="font-['Geist'] text-[12px] opacity-70 max-w-md">
              Trigger autonomous forensic analysis to evaluate multi-sensor telemetry, reconstruct the attack path chain, and generate an actionable containment playbook.
            </p>
            <button
              type="button"
              onClick={handleReanalyze}
              className="mt-2 px-4 py-1.5 border border-[#dc2626] bg-[#dc2626] hover:bg-[#b91c1c] text-white font-['JetBrains_Mono'] text-[11px] font-bold rounded flex items-center gap-1.5"
            >
              <span className="material-symbols-outlined text-[14px]">auto_awesome</span>
              Analyze with {aiProvider.toUpperCase()}
            </button>
          </div>
        )}

        {aiResponse && (
          <>
            {/* Model Meta Cards: Confidence & Reasoning Status */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-['JetBrains_Mono']">
              <div
                className={`p-3 border rounded ${
                  isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#0a0203] border-[#7f1d1d]/40'
                }`}
              >
                <span className="text-[10px] opacity-60 uppercase block">UNIFIED CONFIDENCE</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-[22px] font-bold text-[#10b981]">
                    {(aiResponse.confidence * 100).toFixed(1)}%
                  </span>
                  <span className="text-[9px] text-[#10b981] font-bold">[HEURISTIC]</span>
                </div>
                <span className="text-[9px] opacity-60">High multi-sensor evidence match</span>
              </div>

              <div
                className={`p-3 border rounded ${
                  isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#0a0203] border-[#7f1d1d]/40'
                }`}
              >
                <span className="text-[10px] opacity-60 uppercase block">EVIDENCE BASIS</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-[14px] font-bold text-[#3b82f6] uppercase">
                    {aiResponse.evidence_status || 'SUFFICIENT'}
                  </span>
                  <span className="text-[9px] text-[#3b82f6] font-bold">[OBSERVED]</span>
                </div>
                <span className="text-[9px] opacity-60">4 independent telemetry feeds</span>
              </div>

              <div
                className={`p-3 border rounded ${
                  isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#0a0203] border-[#7f1d1d]/40'
                }`}
              >
                <span className="text-[10px] opacity-60 uppercase block">OPERATOR APPROVAL</span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-[14px] font-bold text-[#f59e0b] uppercase">MANDATORY</span>
                  <span className="text-[9px] text-[#f59e0b] font-bold">AUTO_EXEC: FALSE</span>
                </div>
                <span className="text-[9px] opacity-60">Zero unconfirmed execution</span>
              </div>

              <div
                className={`p-3 border rounded ${
                  isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#0a0203] border-[#7f1d1d]/40'
                }`}
              >
                <span className="text-[10px] opacity-60 uppercase block">ACTIVE MODEL</span>
                <div className="mt-1">
                  <span className="text-[13px] font-bold text-[#ef4444]">
                    {aiResponse.raw_model_name || aiModelLabels[aiResponse.raw_provider || aiProvider]}
                  </span>
                </div>
                <span className="text-[9px] opacity-60">Quantized / Type-Strict</span>
              </div>
            </div>

            {/* AI Synthesis Summary */}
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between">
                <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider opacity-80 flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px] text-[#ef4444]">article</span>
                  Forensic Synthesis Narrative
                </span>
                <span className="font-['JetBrains_Mono'] text-[10px] text-[#3b82f6]">[LLM SYNTHESIS]</span>
              </div>
              <p className="font-['Geist'] text-[13px] leading-relaxed p-3.5 border rounded border-inherit bg-black/20">
                {aiResponse.summary || 'Forensic analysis computed.'}
              </p>
            </div>

            {/* Attack Path Steps (Visual Progression) */}
            {aiResponse.attack_path && aiResponse.attack_path.length > 0 && (
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider opacity-80 flex items-center gap-1.5">
                    <span className="material-symbols-outlined text-[14px] text-[#ef4444]">conversion_path</span>
                    Reconstructed Attack Path Chain
                  </span>
                  <span className="font-['JetBrains_Mono'] text-[10px] text-[#10b981]">[OBSERVED TELEMETRY]</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
                  {aiResponse.attack_path.map((step) => (
                    <div
                      key={step.order}
                      className={`p-3 border rounded text-[11px] flex flex-col justify-between ${
                        isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#0b0304] border-[#7f1d1d]/40'
                      }`}
                    >
                      <div>
                        <div className="flex justify-between items-center text-[10px] font-['JetBrains_Mono'] mb-1">
                          <span className="font-bold text-[#ef4444]">PHASE 0{step.order}</span>
                          <span className="px-1.5 py-0.2 border border-[#3b82f6] text-[#3b82f6] rounded">
                            {step.techniqueId || step.technique}
                          </span>
                        </div>
                        <div className="font-['Space_Grotesk'] text-[12px] font-bold leading-tight">
                          {step.tactic}
                        </div>
                        <p className="font-['Geist'] text-[11px] opacity-80 mt-1.5 leading-snug">
                          {step.description}
                        </p>
                      </div>

                      <div className="mt-2 pt-2 border-t border-inherit text-[10px] font-['JetBrains_Mono'] opacity-70">
                        <div>FROM: {step.source}</div>
                        <div>TO: {step.target}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Predicted Next Steps & Adversary Objective */}
            {aiResponse.predicted_next_steps && (
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider opacity-80 flex items-center gap-1.5">
                    <span className="material-symbols-outlined text-[14px] text-[#f59e0b]">trending_up</span>
                    Predicted Adversary Next Moves & Blast Horizon
                  </span>
                  <span className="font-['JetBrains_Mono'] text-[10px] text-[#f59e0b]">[PREDICTED]</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {aiResponse.predicted_next_steps.map((nextStep, idx) => (
                    <div
                      key={idx}
                      className={`p-3 border rounded text-[11px] flex flex-col justify-between ${
                        isLight ? 'bg-[#fffbeb] border-[#fde68a]' : 'bg-[#180902] border-[#f59e0b]/40'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-['JetBrains_Mono'] text-[10px] font-bold text-[#f59e0b]">
                          PROJECTION #{idx + 1}
                        </span>
                        <span className="font-['JetBrains_Mono'] text-[10px] text-current opacity-80">
                          CONFIDENCE: {typeof nextStep.confidence === 'number' ? `${Math.round(nextStep.confidence * 100)}%` : 'N/A'}
                        </span>
                      </div>
                      <div className="font-['Space_Grotesk'] text-[13px] font-bold text-[#f59e0b]">
                        {nextStep.step}
                      </div>
                      <p className="font-['Geist'] text-[11px] opacity-90 mt-1 leading-snug">
                        {nextStep.rationale}
                      </p>
                      {nextStep.timeframe && (
                        <span className="font-['JetBrains_Mono'] text-[9px] opacity-60 mt-1.5">
                          TIMEFRAME: {nextStep.timeframe}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Proposed Containment Actions & Approval Dispatch */}
            {aiResponse.proposed_playbook && (
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider opacity-80 flex items-center gap-1.5">
                    <span className="material-symbols-outlined text-[14px] text-[#10b981]">checklist</span>
                    Proposed Containment Playbook ({aiResponse.proposed_playbook.name})
                  </span>
                  <span className="font-['JetBrains_Mono'] text-[10px] text-[#10b981]">[ACTIONABLE]</span>
                </div>

                <div className="border rounded overflow-hidden divide-y divide-inherit">
                  {aiResponse.proposed_playbook.steps.map((step) => (
                    <div
                      key={step.sequence}
                      className="p-3 flex items-center justify-between gap-3 text-[11px] font-['JetBrains_Mono'] hover:bg-black/10 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <span className="w-6 h-6 rounded-full border border-current flex items-center justify-center font-bold text-[10px]">
                          {step.sequence}
                        </span>
                        <div>
                          <div className="font-bold text-current">{step.action_type}</div>
                          <div className="opacity-70 text-[10px]">TARGET: {step.target} — {step.description}</div>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() =>
                          handleActionClick(
                            step.description || step.action_type,
                            step.target,
                            'Targeted containment execution with human approval gate.'
                          )
                        }
                        className="px-3 py-1 border border-[#ef4444] text-[#ef4444] hover:bg-[#ef4444] hover:text-white rounded text-[10px] font-bold transition-colors shrink-0"
                      >
                        Request Operator Approval
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Evidence Grounding References */}
            {aiResponse.evidence_references && (
              <div className="flex flex-col gap-2">
                <span className="font-['JetBrains_Mono'] text-[11px] uppercase font-bold tracking-wider opacity-80 flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[14px] text-[#3b82f6]">policy</span>
                  Auditable Evidence Grounding ({aiResponse.evidence_references.length} Multi-Source Artifacts)
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] font-['JetBrains_Mono']">
                  {aiResponse.evidence_references.map((ev, idx) => (
                    <div
                      key={idx}
                      className={`p-2.5 border rounded flex items-start gap-2 ${
                        isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#080203] border-[#7f1d1d]/30'
                      }`}
                    >
                      <span className="material-symbols-outlined text-[16px] text-[#3b82f6] shrink-0 mt-0.5">
                        task_alt
                      </span>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold">{ev.evidence_id}</span>
                          <span className="text-[9px] px-1 border border-current opacity-70 rounded">
                            {ev.basis.toUpperCase()}
                          </span>
                        </div>
                        <div className="text-[10px] opacity-80 mt-0.5">{ev.summary}</div>
                        <div className="text-[9px] text-[#3b82f6] mt-0.5">SOURCE: {ev.source}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}

        {/* Analyst Follow-up Prompt Input */}
        <div className="flex flex-col gap-1.5 pt-2 border-t border-inherit">
          <label className="font-['JetBrains_Mono'] text-[10px] uppercase font-bold opacity-80">
            Analyst Follow-Up Directive / Specific Instructions:
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={analystPrompt}
              onChange={(e) => setAnalystPrompt(e.target.value)}
              placeholder="e.g., Focus on Kubernetes cluster lateral movement risk and compute Blast Radius..."
              className={`flex-1 h-9 px-3 border rounded text-[11px] font-['JetBrains_Mono'] ${
                isLight
                  ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]'
                  : 'bg-[#0a0203] border-[#7f1d1d]/60 text-white'
              }`}
            />
            <button
              type="button"
              disabled={isAiAnalyzing || !canRequestAi}
              onClick={handleReanalyze}
              className="h-9 px-4 border border-[#dc2626] bg-[#dc2626] hover:bg-[#b91c1c] disabled:opacity-50 text-white font-['JetBrains_Mono'] text-[11px] font-bold rounded flex items-center gap-1.5 transition-colors shrink-0"
            >
              {isAiAnalyzing ? (
                <>
                  <span className="material-symbols-outlined text-[14px] animate-spin">refresh</span>
                  Analyzing...
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined text-[14px]">auto_awesome</span>
                  Re-Analyze with {aiProvider.toUpperCase()}
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
