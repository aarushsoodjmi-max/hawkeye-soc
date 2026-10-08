import React, { useState } from 'react';
import { useSoc } from '../context/SocContext';
import { ThemeMode, GraphNode, GraphEdge } from '../types';

interface KnowledgeGraphViewProps {
  theme?: ThemeMode;
}

export const KnowledgeGraphView: React.FC<KnowledgeGraphViewProps> = ({ theme = 'dark' }) => {
  const { knowledgeGraph, traverseGraph } = useSoc();
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(knowledgeGraph.nodes[0] || null);
  const [traversalDepth, setTraversalDepth] = useState(2);
  const isLight = theme === 'light';

  const nodeColorMap: Record<string, string> = {
    user: '#3b82f6',
    asset: '#10b981',
    c2_server: '#ef4444',
    technique: '#f59e0b',
  };

  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
    traverseGraph(node.id, traversalDepth);
  };

  return (
    <div
      id="knowledge-graph-view"
      className="w-full flex flex-col gap-5 p-4 lg:p-6 max-w-7xl mx-auto select-none"
    >
      {/* Header */}
      <div
        className={`p-4 border rounded-lg flex flex-wrap items-center justify-between gap-4 transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]' : 'bg-[#050102] border-[#7f1d1d]/80 text-[#f3f4f6]'
        }`}
      >
        <div>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[22px] text-[#ef4444]">account_tree</span>
            <h2 className="font-['Space_Grotesk'] text-[18px] font-bold tracking-tight">
              Temporal Knowledge Graph & Adversary Topology
            </h2>
          </div>
          <p className="font-['JetBrains_Mono'] text-[11px] opacity-70 mt-0.5">
            GRAPH NODES: {knowledgeGraph.nodes.length} | EDGES: {knowledgeGraph.edges.length} | CORRELATION ENGINE v4.1
          </p>
        </div>

        <div className="flex items-center gap-3 font-['JetBrains_Mono'] text-[11px]">
          <label className="opacity-70">TRAVERSAL DEPTH:</label>
          <select
            value={traversalDepth}
            onChange={(e) => setTraversalDepth(Number(e.target.value))}
            className={`h-8 px-2 border rounded ${
              isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#000000] border-[#7f1d1d]/60 text-white'
            }`}
          >
            <option value="1">1 Hop (Direct Links)</option>
            <option value="2">2 Hops (Subnet Neighbors)</option>
            <option value="3">3 Hops (Blast Radius)</option>
          </select>
        </div>
      </div>

      {/* Main Canvas & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Visual Graph Area (2 cols) */}
        <div
          className={`lg:col-span-2 border rounded-lg p-4 flex flex-col justify-between min-h-[480px] relative transition-colors ${
            isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#030102] border-[#7f1d1d]/80'
          }`}
        >
          {/* Legend */}
          <div className="flex flex-wrap items-center gap-3 font-['JetBrains_Mono'] text-[10px] pb-3 border-b border-inherit">
            <span className="opacity-60 uppercase">ENTITY TYPES:</span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-full bg-[#3b82f6]" /> User
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-full bg-[#10b981]" /> Asset / Host
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-full bg-[#ef4444]" /> C2 Node / Process
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-full bg-[#f59e0b]" /> ATT&CK Technique
            </span>
          </div>

          {/* Interactive Node Layout Grid */}
          <div className="py-6 flex flex-wrap gap-4 items-center justify-center">
            {knowledgeGraph.nodes.map((node) => {
              const isSelected = selectedNode?.id === node.id;
              const color = nodeColorMap[node.type] || '#ef4444';

              return (
                <button
                  key={node.id}
                  type="button"
                  onClick={() => handleNodeClick(node)}
                  className={`p-3 border rounded-lg flex flex-col items-center justify-center transition-all ${
                    isSelected
                      ? 'border-[#ef4444] bg-[#ef4444]/20 scale-105 shadow-[0_0_20px_rgba(239,68,68,0.4)]'
                      : 'border-inherit hover:border-[#ef4444] bg-black/40 hover:scale-102'
                  }`}
                  style={{ minWidth: '150px' }}
                >
                  <span
                    className="w-8 h-8 rounded-full flex items-center justify-center text-white mb-2 shadow"
                    style={{ backgroundColor: color }}
                  >
                    <span className="material-symbols-outlined text-[16px]">
                      {node.type === 'user'
                        ? 'person'
                        : node.type === 'asset'
                        ? 'dns'
                        : node.type === 'c2_server'
                        ? 'radar'
                        : 'terminal'}
                    </span>
                  </span>

                  <span className="font-['Space_Grotesk'] text-[12px] font-bold text-center">
                    {node.name}
                  </span>
                  <span className="font-['JetBrains_Mono'] text-[9px] opacity-60 mt-0.5 uppercase">
                    {node.label}
                  </span>
                  {node.riskScore && (
                    <span className="mt-1 text-[9px] font-['JetBrains_Mono'] text-[#ef4444] font-bold">
                      RISK: {node.riskScore}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Connected Edges Strip */}
          <div className="pt-3 border-t border-inherit flex flex-wrap gap-2 text-[10px] font-['JetBrains_Mono']">
            <span className="opacity-60 uppercase">ACTIVE RELATIONSHIPS:</span>
            {knowledgeGraph.edges.slice(0, 5).map((edge, i) => (
              <span key={i} className="px-2 py-0.5 rounded border border-inherit bg-black/20">
                {edge.source} <strong className="text-[#ef4444]">→ {edge.relationship_type} →</strong> {edge.target}
              </span>
            ))}
          </div>
        </div>

        {/* Selected Entity Dossier (1 col) */}
        {selectedNode && (
          <div
            className={`border rounded-lg p-4 flex flex-col justify-between transition-colors ${
              isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
            }`}
          >
            <div>
              <div className="flex items-center justify-between border-b border-inherit pb-3 mb-3">
                <div>
                  <span className="text-[10px] font-['JetBrains_Mono'] opacity-60 uppercase block">
                    KNOWLEDGE GRAPH ENTITY
                  </span>
                  <h3 className="font-['Space_Grotesk'] text-[16px] font-bold text-[#ef4444]">
                    {selectedNode.name}
                  </h3>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-['JetBrains_Mono'] font-bold border border-inherit">
                  {selectedNode.type.toUpperCase()}
                </span>
              </div>

              <div className="flex flex-col gap-2 font-['JetBrains_Mono'] text-[11px]">
                <div>
                  <span className="opacity-60 text-[9px] uppercase block">LABEL / CLASSIFICATION:</span>
                  <span className="font-bold">{selectedNode.label}</span>
                </div>
                <div>
                  <span className="opacity-60 text-[9px] uppercase block">CRITICALITY LEVEL:</span>
                  <span className="font-bold text-[#ef4444]">{selectedNode.criticality}</span>
                </div>
                {selectedNode.riskScore && (
                  <div>
                    <span className="opacity-60 text-[9px] uppercase block">RISK SCORE:</span>
                    <span className="font-bold text-[#ef4444]">{selectedNode.riskScore} / 100</span>
                  </div>
                )}

                <div className="pt-2 border-t border-inherit">
                  <span className="opacity-60 text-[9px] uppercase block">INCIDENT EDGES (RELATIONSHIPS):</span>
                  <div className="flex flex-col gap-1.5 mt-1">
                    {knowledgeGraph.edges
                      .filter((e) => e.source === selectedNode.id || e.target === selectedNode.id)
                      .map((edge, idx) => (
                        <div key={idx} className="p-2 border rounded border-inherit text-[10px] bg-black/20">
                          <div className="font-bold text-[#ef4444]">{edge.relationship_type}</div>
                          <div className="opacity-70 mt-0.5">
                            {edge.source === selectedNode.id ? `TARGET: ${edge.target}` : `SOURCE: ${edge.source}`}
                          </div>
                          {edge.valid_from && (
                            <div className="opacity-50 text-[9px]">VALID FROM: {edge.valid_from}</div>
                          )}
                          <div className="text-[9px] text-[#10b981]">CONFIDENCE: {typeof edge.confidence === 'number' ? `${Math.round(edge.confidence * 100)}%` : 'N/A'}</div>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-inherit">
              <button
                type="button"
                onClick={() => traverseGraph(selectedNode.id, traversalDepth)}
                className="w-full py-2 border border-[#ef4444] bg-[#ef4444]/20 hover:bg-[#ef4444] hover:text-white text-[#ef4444] rounded text-[11px] font-['JetBrains_Mono'] font-bold transition-all shadow-[0_0_15px_rgba(239,68,68,0.2)]"
              >
                Traverse Entity Sub-Graph ({traversalDepth} Hops)
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
