import React, { useState } from 'react';
import { useSoc } from '../context/SocContext';
import { useAuth } from '../context/AuthContext';
import { ThemeMode, AffectedAsset } from '../types';

interface Asset360ViewProps {
  theme?: ThemeMode;
}

export const Asset360View: React.FC<Asset360ViewProps> = ({ theme = 'dark' }) => {
  const { assets, toggleAssetIsolation, activeIncidentId } = useSoc();
  const { canExecuteActions } = useAuth();
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedAsset, setSelectedAsset] = useState<AffectedAsset | null>(assets[0] || null);

  const isLight = theme === 'light';

  const filteredAssets = assets.filter((asset) => {
    const matchesSearch =
      asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.ip.includes(searchTerm) ||
      asset.role.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || asset.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div
      id="asset-360-view"
      className="w-full flex flex-col gap-5 p-4 lg:p-6 max-w-7xl mx-auto select-none"
    >
      {/* Top Header */}
      <div
        className={`p-4 border rounded-lg flex flex-wrap items-center justify-between gap-4 transition-colors ${
          isLight ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]' : 'bg-[#050102] border-[#7f1d1d]/80 text-[#f3f4f6]'
        }`}
      >
        <div>
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[22px] text-[#ef4444]">devices</span>
            <h2 className="font-['Space_Grotesk'] text-[18px] font-bold tracking-tight">
              Enterprise Asset 360 Inventory & Containment
            </h2>
          </div>
          <p className="font-['JetBrains_Mono'] text-[11px] opacity-70 mt-0.5">
            REAL-TIME MESH // ACTIVE ASSETS: {assets.length} | QUARANTINED: {assets.filter((a) => a.status === 'ISOLATED').length}
          </p>
        </div>

        {/* Filter & Search */}
        <div className="flex items-center gap-2 font-['JetBrains_Mono'] text-[11px]">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search host, IP, role..."
            className={`h-8 px-3 border rounded ${
              isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#000000] border-[#7f1d1d]/60 text-white'
            }`}
          />

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className={`h-8 px-2 border rounded ${
              isLight ? 'bg-[#f8fafc] border-[#cbd5e1]' : 'bg-[#000000] border-[#7f1d1d]/60 text-white'
            }`}
          >
            <option value="ALL">All Statuses</option>
            <option value="COMPROMISED">Compromised</option>
            <option value="ISOLATED">Isolated (Quarantined)</option>
            <option value="MONITORED">Monitored</option>
            <option value="CLEAN">Clean</option>
          </select>
        </div>
      </div>

      {/* Main Grid: Asset Table + Selected Asset Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Assets Table (2 cols) */}
        <div
          className={`lg:col-span-2 border rounded-lg overflow-hidden transition-colors ${
            isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
          }`}
        >
          <div
            className={`p-3.5 border-b flex items-center justify-between ${
              isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#0a0203] border-[#7f1d1d]/60'
            }`}
          >
            <span className="font-['Space_Grotesk'] text-[14px] font-bold">
              Monitored Endpoints & Infrastructure
            </span>
            <span className="font-['JetBrains_Mono'] text-[10px] text-[#3b82f6]">
              COUNT: {filteredAssets.length}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px] font-['JetBrains_Mono'] divide-y divide-inherit">
              <thead>
                <tr className={isLight ? 'bg-[#f1f5f9] text-[#475569]' : 'bg-black/60 text-[#9ca3af]'}>
                  <th className="p-3">HOST NAME</th>
                  <th className="p-3">IP ADDRESS</th>
                  <th className="p-3">CRITICALITY</th>
                  <th className="p-3">STATUS</th>
                  <th className="p-3">BLAST RADIUS</th>
                  <th className="p-3 text-right">CONTAINMENT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-inherit">
                {filteredAssets.map((asset) => {
                  const isIsolated = asset.status === 'ISOLATED';
                  const isCompromised = asset.status === 'COMPROMISED';
                  const isSelected = selectedAsset?.id === asset.id;

                  return (
                    <tr
                      key={asset.id}
                      onClick={() => setSelectedAsset(asset)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? isLight
                            ? 'bg-[#fee2e2]'
                            : 'bg-[#2a0408]'
                          : 'hover:bg-black/10'
                      }`}
                    >
                      <td className="p-3 font-bold">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`w-2 h-2 rounded-full ${
                              isIsolated
                                ? 'bg-[#f59e0b]'
                                : isCompromised
                                ? 'bg-[#ef4444] animate-ping'
                                : 'bg-[#10b981]'
                            }`}
                          />
                          <span className="font-['Space_Grotesk'] text-[13px]">{asset.name}</span>
                        </div>
                        <span className="text-[10px] opacity-60 block mt-0.5">{asset.role}</span>
                      </td>
                      <td className="p-3 text-[#3b82f6]">{asset.ip}</td>
                      <td className="p-3">
                        <span
                          className={`px-1.5 py-0.2 rounded text-[9px] font-bold border ${
                            asset.criticality === 'TIER 0'
                              ? 'border-[#ef4444] text-[#ef4444] bg-[#ef4444]/10'
                              : 'border-[#f59e0b] text-[#f59e0b] bg-[#f59e0b]/10'
                          }`}
                        >
                          {asset.criticality}
                        </span>
                      </td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            isIsolated
                              ? 'border-[#f59e0b] text-[#f59e0b] bg-[#f59e0b]/15'
                              : isCompromised
                              ? 'border-[#ef4444] text-[#ef4444] bg-[#ef4444]/15'
                              : 'border-[#10b981] text-[#10b981] bg-[#10b981]/15'
                          }`}
                        >
                          {asset.status}
                        </span>
                      </td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-1.5 rounded bg-black/40 overflow-hidden">
                            <div
                              className="h-full bg-[#ef4444]"
                              style={{ width: `${asset.blastRadiusScore ?? 0}%` }}
                            />
                          </div>
                          <span className="font-bold">{asset.blastRadiusScore ?? 'N/A'}</span>
                        </div>
                      </td>
                      <td className="p-3 text-right">
                        <button
                          type="button"
                          disabled={!canExecuteActions}
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleAssetIsolation(activeIncidentId, asset.id);
                          }}
                          className={`px-3 py-1 rounded text-[10px] font-bold border transition-all ${
                            isIsolated
                              ? 'border-[#10b981] text-[#10b981] hover:bg-[#10b981] hover:text-white'
                              : 'border-[#ef4444] text-[#ef4444] hover:bg-[#ef4444] hover:text-white'
                          }`}
                        >
                          {isIsolated ? 'Restore Network' : 'Quarantine'}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Asset Deep Inspector (1 col) */}
        {selectedAsset && (
          <div
            className={`border rounded-lg p-4 flex flex-col justify-between transition-colors ${
              isLight ? 'bg-[#ffffff] border-[#cbd5e1]' : 'bg-[#050102] border-[#7f1d1d]/80'
            }`}
          >
            <div>
              <div className="flex items-center justify-between border-b border-inherit pb-3 mb-3">
                <div>
                  <span className="text-[10px] font-['JetBrains_Mono'] opacity-60 uppercase block">
                    ASSET INSPECTION DOSSIER
                  </span>
                  <h3 className="font-['Space_Grotesk'] text-[17px] font-bold text-[#ef4444]">
                    {selectedAsset.name}
                  </h3>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-['JetBrains_Mono'] font-bold border ${
                    selectedAsset.status === 'ISOLATED'
                      ? 'border-[#f59e0b] text-[#f59e0b]'
                      : selectedAsset.status === 'COMPROMISED'
                      ? 'border-[#ef4444] text-[#ef4444]'
                      : 'border-[#10b981] text-[#10b981]'
                  }`}
                >
                  {selectedAsset.status}
                </span>
              </div>

              <div className="flex flex-col gap-2.5 font-['JetBrains_Mono'] text-[11px]">
                <div>
                  <span className="opacity-60 text-[9px] uppercase block">IP ADDRESS:</span>
                  <span className="font-bold text-[#3b82f6]">{selectedAsset.ip}</span>
                </div>
                <div>
                  <span className="opacity-60 text-[9px] uppercase block">OPERATING SYSTEM / KERNEL:</span>
                  <span className="font-bold">{selectedAsset.os}</span>
                </div>
                <div>
                  <span className="opacity-60 text-[9px] uppercase block">ENTERPRISE FUNCTION:</span>
                  <span>{selectedAsset.role}</span>
                </div>
                <div>
                  <span className="opacity-60 text-[9px] uppercase block">CRITICALITY TIER:</span>
                  <span className="font-bold text-[#ef4444]">{selectedAsset.criticality}</span>
                </div>
                <div>
                  <span className="opacity-60 text-[9px] uppercase block">BLAST RADIUS FACTOR:</span>
                  <span className="font-bold">{selectedAsset.blastRadiusScore} / 100</span>
                </div>

                <div className="pt-2 border-t border-inherit">
                  <span className="opacity-60 text-[9px] uppercase block">UPSTREAM & DOWNSTREAM DEPENDENCIES:</span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {selectedAsset.dependencies.map((dep, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 border border-inherit text-[10px] rounded bg-black/20"
                      >
                        {dep}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-inherit">
              <button
                type="button"
                disabled={!canExecuteActions}
                onClick={() => toggleAssetIsolation(activeIncidentId, selectedAsset.id)}
                className={`w-full py-2 border rounded font-['JetBrains_Mono'] text-[11px] font-bold transition-all ${
                  selectedAsset.status === 'ISOLATED'
                    ? 'border-[#10b981] bg-[#10b981]/20 text-[#10b981] hover:bg-[#10b981] hover:text-white'
                    : 'border-[#ef4444] bg-[#ef4444]/20 text-[#ef4444] hover:bg-[#ef4444] hover:text-white shadow-[0_0_15px_rgba(239,68,68,0.3)]'
                }`}
              >
                {selectedAsset.status === 'ISOLATED'
                  ? 'Restore Network Boundary Connectivity'
                  : 'Enforce Endpoint Perimeter Isolation'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
