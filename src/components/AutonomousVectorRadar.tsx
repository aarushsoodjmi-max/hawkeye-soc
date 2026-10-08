import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Severity, ThemeMode, SecurityEvent } from '../types';
import { useSoc } from '../context/SocContext';

export interface RadarVector {
  id: string;
  name: string;
  category: 'c2' | 'exfil' | 'lateral' | 'identity' | 'ingress' | 'cloud';
  severity: Severity;
  bearingDeg: number; // 0 to 360 deg
  distanceRatio: number; // 0.15 (near core) to 0.95 (perimeter edge)
  velocity: string;
  sourceIp?: string;
  sourceHost?: string;
  targetAsset: string;
  mitreId: string;
  mitreTactic: string;
  threatActor?: string;
  confidence: number;
  timeToCrownJewel: string;
  status: 'TRACKING' | 'NEUTRALIZED' | 'LOCKED';
  payloadSummary: string;
  correlatedIncident?: string;
}

const eventCategory = (event: SecurityEvent): RadarVector['category'] => {
  const text = `${event.eventType} ${event.technique || ''}`.toLowerCase();
  if (text.includes('dns') || text.includes('exfil')) return 'exfil';
  if (text.includes('c2') || text.includes('beacon') || text.includes('command')) return 'c2';
  if (text.includes('mfa') || text.includes('cookie') || text.includes('identity')) return 'identity';
  if (text.includes('iam') || text.includes('cloud') || text.includes('assume')) return 'cloud';
  if (text.includes('lsass') || text.includes('lateral') || text.includes('credential')) return 'lateral';
  return 'ingress';
};

// Incident states that still require containment/action. The radar is an
// allowlist: anything else (CONTAINED, MITIGATED, CLOSED, RESOLVED,
// FALSE_POSITIVE, unknown) is treated as inactive and never plotted.
const ACTIVE_INCIDENT_STATUSES = new Set([
  'NEW', 'ACTIVE', 'OPEN', 'TRIAGING', 'INVESTIGATING', 'ACTIVE_CONTAINMENT',
]);
export const isActiveIncidentStatus = (status: unknown): boolean =>
  ACTIVE_INCIDENT_STATUSES.has(String(status ?? '').trim().toUpperCase());

interface AutonomousVectorRadarProps {
  theme?: ThemeMode;
  onSelectIncident?: (id: string) => void;
  isExpandedView?: boolean;
  onToggleExpand?: () => void;
  events?: SecurityEvent[];
}

export const AutonomousVectorRadar: React.FC<AutonomousVectorRadarProps> = ({
  theme = 'dark',
  onSelectIncident,
  isExpandedView = false,
  onToggleExpand,
  events = [],
}) => {
  const isLight = theme === 'light';

  const { incidents } = useSoc();

  // Data/query transformation layer: only events tied to a currently ACTIVE
  // incident (and not themselves contained/blocked/quarantined) become radar
  // vectors. Derived from live incident state, so when the realtime flow
  // moves an incident to contained/closed the vectors drop out on the next
  // update. Nothing here mutates events/incidents used by other views.
  const activeEvents = useMemo(() => {
    const activeIncidentIds = new Set(
      incidents.filter(i => isActiveIncidentStatus(i.status)).map(i => String(i.id)),
    );
    return events.filter(e => {
      if (e.blocked || e.contained || e.quarantined) return false;
      const incidentId = e.correlatedIncident ?? (e as { incidentId?: string | null }).incidentId;
      return incidentId != null && activeIncidentIds.has(String(incidentId));
    });
  }, [events, incidents]);

  const vectors = useMemo<RadarVector[]>(() => activeEvents.map((event, index) => ({
    id: event.id,
    name: event.eventType || event.technique || event.id,
    category: eventCategory(event),
    severity: event.severity,
    bearingDeg: (index * 360) / Math.max(activeEvents.length, 1),
    distanceRatio: 0.35 + (index % 6) * 0.1,
    velocity: 'Not available',
    sourceIp: event.sourceIp,
    sourceHost: event.sourceHost,
    targetAsset: event.destination || event.sourceHost || 'Not available',
    mitreId: event.techniqueId || 'Not available',
    mitreTactic: event.technique || 'Not available',
    confidence: event.riskScore ?? 0,
    timeToCrownJewel: 'Not available',
    // Reflects real backend containment state on the underlying event —
    // never set locally except as an optimistic flip while a request is in flight.
    status: (event.blocked || event.contained || event.quarantined) ? 'NEUTRALIZED' : 'TRACKING',
    payloadSummary: event.rawPayload ? JSON.stringify(event.rawPayload) : 'Not available',
    correlatedIncident: event.correlatedIncident,
  })), [activeEvents]);
  const [selectedVectorId, setSelectedVectorId] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<'ALL' | 'CRITICAL' | 'C2_EXFIL' | 'LATERAL' | 'IDENTITY'>('ALL');
  const [sweepSpeed, setSweepSpeed] = useState<'1x' | '2x' | 'PAUSE'>('1x');
  const [zoomRange, setZoomRange] = useState<'FULL' | 'DMZ' | 'CORE'>('FULL');
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [currentAzimuth, setCurrentAzimuth] = useState<number>(0);
  const [lastPingedVector, setLastPingedVector] = useState<string | null>(null);
  useEffect(() => { if (!vectors.some(v => v.id === selectedVectorId)) setSelectedVectorId(vectors[0]?.id || null); }, [vectors, selectedVectorId]);

  const { blockIp, quarantineHost } = useSoc();
  // Tracks vector ids with a neutralize request in flight, purely for the
  // button's own busy-state — the real NEUTRALIZED status above always comes
  // from the backend-reported event flags, never set locally.
  const [neutralizingIds, setNeutralizingIds] = useState<Set<string>>(new Set());

  const audioCtxRef = useRef<AudioContext | null>(null);

  // Play subtle tactical sonar ping if sound enabled
  const playSonarBlip = (freq = 880) => {
    if (!soundEnabled) return;
    try {
      if (!audioCtxRef.current) {
        const AudioCtx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
        audioCtxRef.current = new AudioCtx();
      }
      const ctx = audioCtxRef.current;
      if (ctx.state === 'suspended') {
        ctx.resume();
      }
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.setValueAtTime(freq, ctx.currentTime);
      gain.gain.setValueAtTime(0.04, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.18);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.19);
    } catch {
      // Audio context might be restricted before user gesture
    }
  };

  // Continuous azimuth tracker to simulate real-time radar sweep bearing
  useEffect(() => {
    if (sweepSpeed === 'PAUSE') return;
    const speedMs = sweepSpeed === '2x' ? 20 : 40;
    const interval = setInterval(() => {
      setCurrentAzimuth((prev) => {
        const next = (prev + 2) % 360;
        // Check if passing near any vector within +/- 5 degrees
        const hit = vectors.find((v) => Math.abs(v.bearingDeg - next) < 4);
        if (hit && hit.id !== lastPingedVector) {
          setLastPingedVector(hit.id);
          playSonarBlip(hit.severity === 'CRITICAL' ? 1050 : 780);
        }
        return next;
      });
    }, speedMs);
    return () => clearInterval(interval);
  }, [sweepSpeed, vectors, lastPingedVector, soundEnabled]);

  // Neutralize vector action — routes to the real backend containment
  // action for whichever entity the vector is actually tied to (source IP
  // takes priority, then source host). No local/synthetic status flip: the
  // vector's status re-derives from the backend-reported event once the
  // action lands and the containing view re-hydrates.
  const handleNeutralize = async (id: string) => {
    const vector = vectors.find((v) => v.id === id);
    if (!vector || vector.status === 'NEUTRALIZED') return;
    setNeutralizingIds((prev) => new Set(prev).add(id));
    try {
      if (vector.sourceIp) {
        await blockIp(vector.sourceIp);
      } else if (vector.sourceHost) {
        await quarantineHost(vector.sourceHost);
      }
    } finally {
      setNeutralizingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  // Filter vectors
  const filteredVectors = useMemo(() => {
    return vectors.filter((v) => {
      if (categoryFilter === 'CRITICAL') return v.severity === 'CRITICAL';
      if (categoryFilter === 'C2_EXFIL') return v.category === 'c2' || v.category === 'exfil';
      if (categoryFilter === 'LATERAL') return v.category === 'lateral';
      if (categoryFilter === 'IDENTITY') return v.category === 'identity' || v.category === 'cloud';
      return true;
    });
  }, [vectors, categoryFilter]);

  const selectedVector = useMemo(
    () => vectors.find((v) => v.id === selectedVectorId) || filteredVectors[0] || null,
    [vectors, selectedVectorId, filteredVectors]
  );

  // Zoom scale multipliers: FULL (1x), DMZ (1.4x), CORE (2.2x)
  const zoomFactor = zoomRange === 'CORE' ? 2.2 : zoomRange === 'DMZ' ? 1.4 : 1.0;

  // Radar dimensions in SVG units (radius = 120, center = 150, 150)
  const CENTER = 150;
  const MAX_RADIUS = 125;

  const getCoordinates = (bearingDeg: number, distanceRatio: number) => {
    const rad = ((bearingDeg - 90) * Math.PI) / 180;
    // Cap effective distance with zoom
    const effectiveDist = Math.min(distanceRatio * zoomFactor, 1.05);
    const r = effectiveDist * MAX_RADIUS;
    const x = CENTER + r * Math.cos(rad);
    const y = CENTER + r * Math.sin(rad);
    return { x, y, effectiveDist };
  };

  // Trajectory end toward center core
  const getTrajectoryPath = (v: RadarVector) => {
    const { x, y } = getCoordinates(v.bearingDeg, v.distanceRatio);
    return `M ${x} ${y} L ${CENTER} ${CENTER}`;
  };

  return (
    <div
      id="autonomous-vector-radar-container"
      className={`border flex flex-col relative transition-all duration-300 select-none ${
        isExpandedView ? 'p-5 w-full' : 'p-3 w-full'
      } ${
        isLight
          ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a] shadow-sm'
          : 'bg-[#000000] border-[#7f1d1d]/60 text-[#e5e1e5] shadow-[0_0_30px_rgba(220,38,38,0.15)]'
      }`}
    >
      {/* Header & Status Bar */}
      <div
        className={`flex flex-wrap items-center justify-between gap-2 pb-2.5 border-b ${
          isLight ? 'border-[#e2e8f0]' : 'border-[#7f1d1d]/60'
        }`}
      >
        <div className="flex items-center gap-2">
          <div className="relative flex items-center justify-center">
            <span className="w-2.5 h-2.5 rounded-full bg-[#ef4444] animate-ping absolute" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#ef4444]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span
                className={`font-['Space_Grotesk'] text-[13px] font-bold uppercase tracking-wider ${
                  isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
                }`}
              >
                AUTONOMOUS VECTOR RADAR
              </span>
              <span
                className={`font-['JetBrains_Mono'] text-[9.5px] px-1.5 py-0.5 border font-semibold ${
                  isLight
                    ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c]'
                    : 'bg-[#7f1d1d]/60 border-[#ef4444] text-[#fee2e2]'
                }`}
              >
                360° THREAT TELEMETRY
              </span>
            </div>
            <div
              className={`font-['JetBrains_Mono'] text-[10px] mt-0.5 flex items-center gap-3 ${
                isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'
              }`}
            >
              <span>AZM BEARING: <strong className={isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}>{String(currentAzimuth).padStart(3, '0')}°</strong></span>
              <span>•</span>
              <span>TRACKED VECTORS: <strong className={isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}>{filteredVectors.length} ACTIVE</strong></span>
              <span>•</span>
              <span>PERIMETER LOCK: <strong className={isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}>ENGAGED</strong></span>
            </div>
          </div>
        </div>

        {/* Tactical Quick Controls */}
        <div className="flex items-center gap-1.5">
          {/* Audio Sonar Toggle */}
          <button
            type="button"
            id="btn-radar-audio-toggle"
            onClick={() => {
              setSoundEnabled(!soundEnabled);
              if (!soundEnabled) playSonarBlip(920);
            }}
            title={soundEnabled ? 'Disable Sonar Ping Audio' : 'Enable Tactical Sonar Audio'}
            className={`h-7 px-2 border font-['JetBrains_Mono'] text-[10px] flex items-center gap-1 transition-colors ${
              soundEnabled
                ? isLight
                  ? 'bg-[#dc2626] border-[#dc2626] text-[#ffffff]'
                  : 'bg-[#7f1d1d] border-[#ef4444] text-[#ffffff]'
                : isLight
                ? 'bg-[#f8fafc] border-[#cbd5e1] text-[#64748b] hover:text-[#0f172a] hover:border-[#dc2626]'
                : 'bg-[#050102] border-[#7f1d1d]/60 text-[#9ca3af] hover:text-[#ffffff]'
            }`}
          >
            <span className="material-symbols-outlined text-[13px]">
              {soundEnabled ? 'volume_up' : 'volume_off'}
            </span>
            <span className="hidden sm:inline">{soundEnabled ? 'SONAR ON' : 'MUTE'}</span>
          </button>

          {/* Speed Toggle */}
          <div className={`flex border overflow-hidden text-[10px] font-['JetBrains_Mono'] ${
            isLight ? 'border-[#cbd5e1]' : 'border-[#7f1d1d]/60'
          }`}>
            <button
              type="button"
              id="btn-radar-speed-1x"
              onClick={() => setSweepSpeed('1x')}
              className={`px-1.5 py-1 transition-colors ${
                sweepSpeed === '1x'
                  ? 'bg-[#dc2626] text-[#ffffff] font-bold'
                  : isLight
                  ? 'bg-[#ffffff] text-[#64748b] hover:bg-[#fee2e2]'
                  : 'bg-[#000000] text-[#9ca3af] hover:bg-[#1a0508]'
              }`}
            >
              1X
            </button>
            <button
              type="button"
              id="btn-radar-speed-2x"
              onClick={() => setSweepSpeed('2x')}
              className={`px-1.5 py-1 border-l transition-colors ${
                isLight ? 'border-[#cbd5e1]' : 'border-[#7f1d1d]/60'
              } ${
                sweepSpeed === '2x'
                  ? 'bg-[#dc2626] text-[#ffffff] font-bold'
                  : isLight
                  ? 'bg-[#ffffff] text-[#64748b] hover:bg-[#fee2e2]'
                  : 'bg-[#000000] text-[#9ca3af] hover:bg-[#1a0508]'
              }`}
            >
              2X
            </button>
            <button
              type="button"
              id="btn-radar-speed-pause"
              onClick={() => setSweepSpeed(sweepSpeed === 'PAUSE' ? '1x' : 'PAUSE')}
              className={`px-1.5 py-1 border-l transition-colors ${
                isLight ? 'border-[#cbd5e1]' : 'border-[#7f1d1d]/60'
              } ${
                sweepSpeed === 'PAUSE'
                  ? isLight
                    ? 'bg-[#b91c1c] text-[#ffffff] font-bold'
                    : 'bg-[#7f1d1d] text-[#ffffff] font-bold'
                  : isLight
                  ? 'bg-[#ffffff] text-[#64748b] hover:bg-[#fee2e2]'
                  : 'bg-[#000000] text-[#9ca3af] hover:bg-[#1a0508]'
              }`}
            >
              {sweepSpeed === 'PAUSE' ? 'RESUME' : 'HOLD'}
            </button>
          </div>

          {/* Zoom Selector */}
          <div className={`flex border overflow-hidden text-[10px] font-['JetBrains_Mono'] ${
            isLight ? 'border-[#cbd5e1]' : 'border-[#7f1d1d]/60'
          }`}>
            <button
              type="button"
              id="btn-radar-zoom-full"
              onClick={() => setZoomRange('FULL')}
              className={`px-1.5 py-1 transition-colors ${
                zoomRange === 'FULL'
                  ? isLight
                    ? 'bg-[#dc2626] text-[#ffffff] font-bold'
                    : 'bg-[#7f1d1d] text-[#ffffff] font-bold'
                  : isLight
                  ? 'bg-[#ffffff] text-[#64748b]'
                  : 'bg-[#000000] text-[#9ca3af]'
              }`}
            >
              FULL
            </button>
            <button
              type="button"
              id="btn-radar-zoom-dmz"
              onClick={() => setZoomRange('DMZ')}
              className={`px-1.5 py-1 border-l transition-colors ${
                isLight ? 'border-[#cbd5e1]' : 'border-[#7f1d1d]/60'
              } ${
                zoomRange === 'DMZ'
                  ? isLight
                    ? 'bg-[#dc2626] text-[#ffffff] font-bold'
                    : 'bg-[#7f1d1d] text-[#ffffff] font-bold'
                  : isLight
                  ? 'bg-[#ffffff] text-[#64748b]'
                  : 'bg-[#000000] text-[#9ca3af]'
              }`}
            >
              DMZ
            </button>
            <button
              type="button"
              id="btn-radar-zoom-core"
              onClick={() => setZoomRange('CORE')}
              className={`px-1.5 py-1 border-l transition-colors ${
                isLight ? 'border-[#cbd5e1]' : 'border-[#7f1d1d]/60'
              } ${
                zoomRange === 'CORE'
                  ? isLight
                    ? 'bg-[#dc2626] text-[#ffffff] font-bold'
                    : 'bg-[#7f1d1d] text-[#ffffff] font-bold'
                  : isLight
                  ? 'bg-[#ffffff] text-[#64748b]'
                  : 'bg-[#000000] text-[#9ca3af]'
              }`}
            >
              CORE
            </button>
          </div>

          {/* Expand / Minimize Toggle */}
          {onToggleExpand && (
            <button
              type="button"
              id="btn-radar-expand-toggle"
              onClick={onToggleExpand}
              title={isExpandedView ? 'Dock Radar View' : 'Expand Radar Command Center'}
              className={`w-7 h-7 flex items-center justify-center border transition-colors ${
                isLight
                  ? 'border-[#cbd5e1] bg-[#ffffff] text-[#64748b] hover:text-[#0f172a] hover:border-[#dc2626]'
                  : 'border-[#7f1d1d]/60 bg-[#000000] text-[#9ca3af] hover:text-[#ffffff]'
              }`}
            >
              <span className="material-symbols-outlined text-[15px]">
                {isExpandedView ? 'close_fullscreen' : 'open_in_full'}
              </span>
            </button>
          )}
        </div>
      </div>

      {/* Vector Category Filter Chips */}
      <div className="flex flex-wrap items-center gap-1.5 py-2 text-[10px] font-['JetBrains_Mono']">
        <span className={`text-[9px] uppercase tracking-wider mr-1 font-semibold ${
          isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]/80'
        }`}>
          VECTORS:
        </span>
        {(
          [
            { id: 'ALL', label: 'ALL THREATS', count: vectors.length },
            { id: 'CRITICAL', label: 'CRITICAL BREACH', count: vectors.filter((v) => v.severity === 'CRITICAL').length },
            { id: 'C2_EXFIL', label: 'C2 & EXFIL', count: vectors.filter((v) => v.category === 'c2' || v.category === 'exfil').length },
            { id: 'LATERAL', label: 'LATERAL MOVEMENT', count: vectors.filter((v) => v.category === 'lateral').length },
            { id: 'IDENTITY', label: 'IDENTITY / CLOUD', count: vectors.filter((v) => v.category === 'identity' || v.category === 'cloud').length },
          ] as const
        ).map((chip) => (
          <button
            key={chip.id}
            type="button"
            onClick={() => setCategoryFilter(chip.id)}
            className={`px-2 py-0.5 border font-medium flex items-center gap-1.5 transition-colors ${
              categoryFilter === chip.id
                ? isLight
                  ? 'bg-[#fee2e2] border-[#dc2626] text-[#b91c1c] font-bold'
                  : 'bg-[#7f1d1d] border-[#ef4444] text-[#ffffff]'
                : isLight
                ? 'bg-[#f8fafc] border-[#cbd5e1] text-[#64748b] hover:border-[#dc2626] hover:text-[#0f172a]'
                : 'bg-[#000000] border-[#7f1d1d]/60 text-[#9ca3af] hover:bg-[#1a0508] hover:text-[#ffffff]'
            }`}
          >
            <span>{chip.label}</span>
            <span
              className={`px-1 py-0 text-[8.5px] rounded ${
                categoryFilter === chip.id
                  ? isLight
                    ? 'bg-[#dc2626] text-[#ffffff]'
                    : 'bg-[#ef4444] text-[#ffffff]'
                  : isLight
                  ? 'bg-[#e2e8f0] text-[#475569]'
                  : 'bg-[#1a0508] text-[#ff8080]'
              }`}
            >
              {chip.count}
            </span>
          </button>
        ))}
      </div>

      {/* Main Radar Screen & Tactical Telemetry Side-by-Side */}
      <div className={`grid ${isExpandedView ? 'grid-cols-1 lg:grid-cols-12' : 'grid-cols-1 md:grid-cols-12'} gap-4 pt-1 items-start`}>
        {/* Radar Stage Canvas (7 Cols) */}
        <div className={`${isExpandedView ? 'lg:col-span-7' : 'md:col-span-7'} flex flex-col items-center justify-center relative p-2`}>
          <div className="relative w-full max-w-[340px] aspect-square flex items-center justify-center">
            {/* Tactical Red Ambient Glow behind radar disc */}
            <div className="absolute w-72 h-72 rounded-full bg-[#dc2626]/[0.14] blur-3xl pointer-events-none" />

            {/* SVG Polar Radar Display */}
            <svg
              viewBox="0 0 300 300"
              className="w-full h-full drop-shadow-[0_0_20px_rgba(220,38,38,0.22)] select-none relative z-10"
            >
              <defs>
                {/* Radial background gradient with pure deep black & red aura */}
                <radialGradient id="radar-bg-gradient" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#120306" stopOpacity="1" />
                  <stop offset="65%" stopColor="#080102" stopOpacity="1" />
                  <stop offset="100%" stopColor="#000000" stopOpacity="1" />
                </radialGradient>

                {/* Cyber red radar sweep phosphor tail */}
                <linearGradient id="sweep-beam-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#ff2a2a" stopOpacity="0.45" />
                  <stop offset="80%" stopColor="#ff5451" stopOpacity="0.1" />
                  <stop offset="100%" stopColor="#ff2a2a" stopOpacity="0" />
                </linearGradient>

                {/* Core crown-jewel glow */}
                <radialGradient id="core-glow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.85" />
                  <stop offset="60%" stopColor="#dc2626" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#dc2626" stopOpacity="0" />
                </radialGradient>
              </defs>

              {/* Radar circular base */}
              <circle
                cx={CENTER}
                cy={CENTER}
                r={MAX_RADIUS}
                fill="url(#radar-bg-gradient)"
                stroke="#7f1d1d"
                strokeWidth="2"
              />

              {/* Concentric Range Rings */}
              {/* Ring 4: Perimeter (100%) */}
              <circle
                cx={CENTER}
                cy={CENTER}
                r={MAX_RADIUS}
                fill="none"
                stroke="#7f1d1d"
                strokeWidth="1.2"
                strokeDasharray="4 2"
              />
              {/* Ring 3: DMZ Ingress (75%) */}
              <circle
                cx={CENTER}
                cy={CENTER}
                r={MAX_RADIUS * 0.75}
                fill="none"
                stroke="#7f1d1d"
                strokeWidth="1"
                strokeOpacity="0.8"
              />
              {/* Ring 2: Internal Workloads (50%) */}
              <circle
                cx={CENTER}
                cy={CENTER}
                r={MAX_RADIUS * 0.5}
                fill="none"
                stroke="#991b1b"
                strokeWidth="1"
                strokeOpacity="0.85"
              />
              {/* Ring 1: Crown Jewels Core (25%) */}
              <circle
                cx={CENTER}
                cy={CENTER}
                r={MAX_RADIUS * 0.25}
                fill="none"
                stroke="#dc2626"
                strokeWidth="1.2"
                strokeDasharray="3 3"
                strokeOpacity="0.9"
              />

              {/* Range Ring Labels */}
              <text
                x={CENTER + 4}
                y={CENTER - MAX_RADIUS * 0.25 + 10}
                fill="#ef4444"
                fontSize="7"
                fontFamily="JetBrains Mono"
                fontWeight="bold"
              >
                VAULT CORE
              </text>
              <text
                x={CENTER + 4}
                y={CENTER - MAX_RADIUS * 0.5 + 9}
                fill="#ff8580"
                fontSize="6.5"
                fontFamily="JetBrains Mono"
              >
                K8S CLUSTER
              </text>
              <text
                x={CENTER + 4}
                y={CENTER - MAX_RADIUS * 0.75 + 9}
                fill="#ff8580"
                fontSize="6.5"
                fontFamily="JetBrains Mono"
              >
                DMZ GATEWAY
              </text>
              <text
                x={CENTER + 4}
                y={CENTER - MAX_RADIUS + 10}
                fill="#ff8580"
                fontSize="6.5"
                fontFamily="JetBrains Mono"
              >
                PERIMETER / CLOUD
              </text>

              {/* Crosshair Axes & Degree Ticks */}
              <line
                x1={CENTER - MAX_RADIUS}
                y1={CENTER}
                x2={CENTER + MAX_RADIUS}
                y2={CENTER}
                stroke="#7f1d1d"
                strokeWidth="0.8"
                strokeOpacity="0.7"
              />
              <line
                x1={CENTER}
                y1={CENTER - MAX_RADIUS}
                x2={CENTER}
                y2={CENTER + MAX_RADIUS}
                stroke="#7f1d1d"
                strokeWidth="0.8"
                strokeOpacity="0.7"
              />
              {/* Diagonal 45 deg guide lines */}
              <line
                x1={CENTER - MAX_RADIUS * 0.707}
                y1={CENTER - MAX_RADIUS * 0.707}
                x2={CENTER + MAX_RADIUS * 0.707}
                y2={CENTER + MAX_RADIUS * 0.707}
                stroke="#7f1d1d"
                strokeWidth="0.5"
                strokeDasharray="2 4"
                strokeOpacity="0.5"
              />
              <line
                x1={CENTER - MAX_RADIUS * 0.707}
                y1={CENTER + MAX_RADIUS * 0.707}
                x2={CENTER + MAX_RADIUS * 0.707}
                y2={CENTER - MAX_RADIUS * 0.707}
                stroke="#7f1d1d"
                strokeWidth="0.5"
                strokeDasharray="2 4"
                strokeOpacity="0.5"
              />

              {/* Cardinal Angle Labels */}
              <text x={CENTER} y="15" textAnchor="middle" fill="#dc2626" fontSize="8" fontFamily="JetBrains Mono" fontWeight="bold">
                000° [INGRESS]
              </text>
              <text x="288" y={CENTER + 3} textAnchor="end" fill="#9ca3af" fontSize="8" fontFamily="JetBrains Mono">
                090° [LATERAL]
              </text>
              <text x={CENTER} y="293" textAnchor="middle" fill="#dc2626" fontSize="8" fontFamily="JetBrains Mono" fontWeight="bold">
                180° [EXFIL]
              </text>
              <text x="12" y={CENTER + 3} textAnchor="start" fill="#9ca3af" fontSize="8" fontFamily="JetBrains Mono">
                270° [AUTH]
              </text>

              {/* Dynamic Rotating Sweep Beam & Trailing Phosphor Fan */}
              {sweepSpeed !== 'PAUSE' && (
                <g transform={`rotate(${currentAzimuth} ${CENTER} ${CENTER})`}>
                  {/* Trailing wedge / fan (45 deg sweep glow) */}
                  <path
                    d={`M ${CENTER} ${CENTER} L ${CENTER} ${CENTER - MAX_RADIUS} A ${MAX_RADIUS} ${MAX_RADIUS} 0 0 0 ${
                      CENTER - MAX_RADIUS * Math.sin((45 * Math.PI) / 180)
                    } ${CENTER - MAX_RADIUS * Math.cos((45 * Math.PI) / 180)} Z`}
                    fill="url(#sweep-beam-grad)"
                  />
                  {/* Leading sharp radar sweep line */}
                  <line
                    x1={CENTER}
                    y1={CENTER}
                    x2={CENTER}
                    y2={CENTER - MAX_RADIUS}
                    stroke="#ff3b38"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                  {/* Glow dot at outer sweep head */}
                  <circle cx={CENTER} cy={CENTER - MAX_RADIUS} r="3" fill="#ff0022" />
                </g>
              )}

              {/* Active Trajectory Lines for Tracked Vectors */}
              {filteredVectors.map((v) => {
                const isSelected = selectedVector?.id === v.id;
                const traj = getTrajectoryPath(v);
                return (
                  <path
                    key={`traj-${v.id}`}
                    d={traj}
                    fill="none"
                    stroke={
                      v.status === 'NEUTRALIZED'
                        ? '#10b981'
                        : isSelected
                        ? '#ff0022'
                        : v.severity === 'CRITICAL'
                        ? '#ef4444'
                        : '#f59e0b'
                    }
                    strokeWidth={isSelected ? '1.8' : '1'}
                    strokeDasharray={isSelected ? '3 2' : '2 4'}
                    strokeOpacity={isSelected ? 0.9 : 0.45}
                  />
                );
              })}

              {/* Threat Vector Blips */}
              {filteredVectors.map((v) => {
                const { x, y } = getCoordinates(v.bearingDeg, v.distanceRatio);
                const isSelected = selectedVector?.id === v.id;
                const isHitBySweep = Math.abs(currentAzimuth - v.bearingDeg) < 14;
                const isNeutralized = v.status === 'NEUTRALIZED';

                return (
                  <g
                    key={v.id}
                    className="cursor-pointer"
                    onClick={() => setSelectedVectorId(v.id)}
                  >
                    {/* Pulsing ring if selected or hit by sweep */}
                    {(isSelected || isHitBySweep) && !isNeutralized && (
                      <circle
                        cx={x}
                        cy={y}
                        r={isSelected ? '11' : '8'}
                        fill="none"
                        stroke="#ff2a2a"
                        strokeWidth="1.2"
                        className="animate-ping"
                      />
                    )}

                    {/* Outer Target Lock Box if selected */}
                    {isSelected && (
                      <rect
                        x={x - 8}
                        y={y - 8}
                        width="16"
                        height="16"
                        fill="none"
                        stroke="#ff0022"
                        strokeWidth="1.5"
                        strokeDasharray="3 2"
                      />
                    )}

                    {/* Vector Node Marker */}
                    <circle
                      cx={x}
                      cy={y}
                      r={isSelected ? '4.5' : '3.5'}
                      fill={
                        isNeutralized
                          ? '#10b981'
                          : v.severity === 'CRITICAL'
                          ? '#ef4444'
                          : v.severity === 'HIGH'
                          ? '#f59e0b'
                          : '#3b82f6'
                      }
                      stroke="#000000"
                      strokeWidth="1"
                    />

                    {/* Target Callout Tag */}
                    <text
                      x={x + 6}
                      y={y + 3}
                      fill={
                        isSelected
                          ? '#ff0022'
                          : isNeutralized
                          ? '#10b981'
                          : '#ffffff'
                      }
                      fontSize={isSelected ? '8' : '7'}
                      fontFamily="JetBrains Mono"
                      fontWeight={isSelected ? 'bold' : 'normal'}
                    >
                      {v.id.replace('VEC-', '')}
                    </text>
                  </g>
                );
              })}

              {/* Center Crown-Jewels Protected Vault Core */}
              <circle cx={CENTER} cy={CENTER} r="16" fill="url(#core-glow)" />
              <circle
                cx={CENTER}
                cy={CENTER}
                r={6.5}
                fill="#dc2626"
                stroke="#000000"
                strokeWidth="1.5"
              />
              <circle cx={CENTER} cy={CENTER} r="2" fill="#ffffff" />
            </svg>

            {/* Radar Center Shield Badge Overlay */}
            <div className="absolute bottom-1 right-2 pointer-events-none text-right">
              <span className="font-['JetBrains_Mono'] text-[8.5px] uppercase font-bold tracking-wider text-[#9ca3af]">
                RANGE: {zoomRange} // {zoomFactor}X
              </span>
            </div>
          </div>

          {/* Quick Radar Legend */}
          <div className="w-full flex items-center justify-between text-[9.5px] font-['JetBrains_Mono'] pt-2 mt-1 border-t border-dashed border-[#7f1d1d]/40">
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#ef4444]" /> Critical
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#f59e0b]" /> High
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#3b82f6]" /> Med/Low
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#10b981]" /> Neutralized
              </span>
            </div>
            <span className="font-semibold text-[#ef4444]">
              PROD VAULT INTEGRITY: 94.2%
            </span>
          </div>
        </div>

        {/* Tactical Vector Telemetry HUD Panel (5 Cols) */}
        <div className={`${isExpandedView ? 'lg:col-span-5' : 'md:col-span-5'} flex flex-col space-y-3`}>
          {selectedVector ? (
            <div
              className={`p-3.5 border flex flex-col space-y-2.5 shadow-sm transition-colors ${
                isLight
                  ? 'bg-[#ffffff] border-[#e2e8f0]'
                  : 'bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]'
              }`}
            >
              {/* Header of Selected Vector */}
              <div className={`flex items-start justify-between pb-2 border-b ${
                isLight ? 'border-[#e2e8f0]' : 'border-[#7f1d1d]/40'
              }`}>
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`font-['JetBrains_Mono'] text-[12px] font-bold ${
                        selectedVector.status === 'NEUTRALIZED'
                          ? 'text-[#10b981]'
                          : isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'
                      }`}
                    >
                      {selectedVector.id}
                    </span>
                    <span
                      className={`px-1.5 py-0.2 text-[9px] font-bold font-['JetBrains_Mono'] border ${
                        selectedVector.severity === 'CRITICAL'
                          ? 'bg-[#dc2626] text-[#ffffff] border-[#dc2626]'
                          : selectedVector.severity === 'HIGH'
                          ? 'bg-[#f59e0b] text-[#ffffff] border-[#f59e0b]'
                          : 'bg-[#3b82f6] text-[#ffffff] border-[#3b82f6]'
                      }`}
                    >
                      {selectedVector.severity}
                    </span>
                    {selectedVector.status === 'NEUTRALIZED' && (
                      <span className="px-1.5 py-0.2 text-[9px] font-bold font-['JetBrains_Mono'] bg-[#10b981] text-[#ffffff]">
                        NEUTRALIZED
                      </span>
                    )}
                  </div>
                  <div
                    className={`font-['Space_Grotesk'] text-[13.5px] font-bold mt-1 ${
                      isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'
                    }`}
                  >
                    {selectedVector.name}
                  </div>
                </div>

                <div className="text-right font-['JetBrains_Mono']">
                  <div className={`text-[9px] uppercase ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>PROXIMITY</div>
                  <div className={`text-[12px] font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                    {Math.round(selectedVector.distanceRatio * 100)}%
                  </div>
                </div>
              </div>

              {/* Vector Flight Telemetry Grid */}
              <div className="grid grid-cols-2 gap-2 text-[10.5px] font-['JetBrains_Mono']">
                <div
                  className={`p-2 border ${
                    isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]/50'
                  }`}
                >
                  <span className={`text-[9px] block uppercase ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                    AZIMUTH / BEARING
                  </span>
                  <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>
                    {String(selectedVector.bearingDeg).padStart(3, '0')}° POLAR
                  </span>
                </div>

                <div
                  className={`p-2 border ${
                    isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]/50'
                  }`}
                >
                  <span className={`text-[9px] block uppercase ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                    PROPAGATION VELOCITY
                  </span>
                  <span className={`font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>{selectedVector.velocity}</span>
                </div>

                <div
                  className={`p-2 border ${
                    isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]/50'
                  }`}
                >
                  <span className={`text-[9px] block uppercase ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                    MITRE ATT&amp;CK
                  </span>
                  <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ff8080]'}`}>
                    {selectedVector.mitreId} ({selectedVector.mitreTactic})
                  </span>
                </div>

                <div
                  className={`p-2 border ${
                    isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]/50'
                  }`}
                >
                  <span className={`text-[9px] block uppercase ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                    EST. TIME TO VAULT
                  </span>
                  <span
                    className={`font-bold ${
                      selectedVector.status === 'NEUTRALIZED'
                        ? 'text-[#10b981]'
                        : isLight
                        ? 'text-[#b91c1c]'
                        : 'text-[#ef4444]'
                    }`}
                  >
                    {selectedVector.status === 'NEUTRALIZED' ? 'BLOCKED' : selectedVector.timeToCrownJewel}
                  </span>
                </div>
              </div>

              {/* Threat Attribution & Entity Details */}
              <div
                className={`p-2.5 border text-[11px] font-['JetBrains_Mono'] space-y-1 ${
                  isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]/50'
                }`}
              >
                <div className="flex justify-between items-center">
                  <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>TARGET ASSET:</span>
                  <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ef4444]'}`}>{selectedVector.targetAsset}</span>
                </div>
                {selectedVector.sourceIp && (
                  <div className="flex justify-between items-center">
                    <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>SOURCE IP:</span>
                    <span className={`font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>{selectedVector.sourceIp}</span>
                  </div>
                )}
                {selectedVector.threatActor && (
                  <div className="flex justify-between items-center">
                    <span className={isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}>ADVERSARY:</span>
                    <span className={`font-bold ${isLight ? 'text-[#b91c1c]' : 'text-[#ff8080]'}`}>{selectedVector.threatActor}</span>
                  </div>
                )}
                <div className={`pt-1 text-[10px] leading-relaxed border-t ${
                  isLight ? 'border-[#e2e8f0] text-[#64748b]' : 'border-[#7f1d1d]/30 text-[#9ca3af]'
                }`}>
                  <span className={`font-semibold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                    PAYLOAD SIGNATURE:{' '}
                  </span>
                  <span>{selectedVector.payloadSummary}</span>
                </div>
              </div>

              {/* Tactical Intervention Trigger Buttons */}
              <div className="space-y-1.5 pt-1">
                {selectedVector.status !== 'NEUTRALIZED' ? (
                  <button
                    type="button"
                    id="btn-radar-neutralize-vector"
                    disabled={!(selectedVector.sourceIp || selectedVector.sourceHost) || neutralizingIds.has(selectedVector.id)}
                    onClick={() => void handleNeutralize(selectedVector.id)}
                    className="w-full py-2 px-3 bg-[#dc2626] hover:bg-[#ef4444] disabled:opacity-50 disabled:cursor-not-allowed text-[#ffffff] border border-[#ff5451] font-['JetBrains_Mono'] text-[11px] font-bold flex items-center justify-between transition-colors shadow-[0_0_12px_rgba(239,68,68,0.25)]"
                  >
                    <span className="flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[15px]">security</span>
                      {neutralizingIds.has(selectedVector.id)
                        ? 'Dispatching Interception...'
                        : (selectedVector.sourceIp || selectedVector.sourceHost)
                        ? 'Neutralize Vector'
                        : 'Vector Interception Unavailable'}
                    </span>
                    <span className="text-[9px] uppercase px-1.5 py-0.5 bg-[#000000]/40 rounded text-[#fee2e2]">
                      {selectedVector.sourceIp ? `BLOCK ${selectedVector.sourceIp}` : selectedVector.sourceHost ? `QUARANTINE ${selectedVector.sourceHost}` : 'NO TARGET'}
                    </span>
                  </button>
                ) : (
                  <div className="w-full py-2 px-3 bg-[#10b981]/20 border border-[#10b981] text-[#10b981] font-['JetBrains_Mono'] text-[11px] font-bold flex items-center justify-center gap-2">
                    <span className="material-symbols-outlined text-[15px]">check_circle</span>
                    Threat Vector Neutralized &amp; Null-Routed
                  </div>
                )}

                {selectedVector.correlatedIncident && onSelectIncident && (
                  <button
                    type="button"
                    id="btn-radar-view-case"
                    onClick={() => onSelectIncident(selectedVector.correlatedIncident!)}
                    className={`w-full py-1.5 px-3 border font-['JetBrains_Mono'] text-[10.5px] font-semibold flex items-center justify-between transition-colors ${
                      isLight
                        ? 'bg-[#ffffff] border-[#cbd5e1] hover:border-[#dc2626] text-[#0f172a]'
                        : 'bg-[#000000] border-[#7f1d1d] hover:border-[#ef4444] text-[#ffffff]'
                    }`}
                  >
                    <span className="flex items-center gap-1.5">
                      <span className="material-symbols-outlined text-[14px]">open_in_new</span>
                      Open Correlated Incident Dossier ({selectedVector.correlatedIncident})
                    </span>
                    <span className="material-symbols-outlined text-[12px]">arrow_forward</span>
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div
              className={`p-6 border flex flex-col items-center justify-center text-center ${
                isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#050102] border-[#7f1d1d]/60'
              }`}
            >
              <span className="material-symbols-outlined text-[32px] text-[#dc2626] mb-2">
                radar
              </span>
              <span className={`font-['Space_Grotesk'] text-[13px] font-bold ${isLight ? 'text-[#0f172a]' : 'text-[#ffffff]'}`}>
                No Threat Vector Selected
              </span>
              <span className={`text-[11px] font-['JetBrains_Mono'] mt-1 ${isLight ? 'text-[#64748b]' : 'text-[#9ca3af]'}`}>
                Click on any blip in the 360° radar screen to lock target telemetry.
              </span>
            </div>
          )}

          {/* Quick List of All Active Target Vectors */}
          <div
            className="border p-2.5 space-y-1.5 bg-[#050102] border-[#7f1d1d]/60 shadow-[0_0_20px_rgba(185,28,28,0.1)]"
          >
            <div className="flex justify-between items-center pb-1 border-b border-[#7f1d1d]/40">
              <span
                className="font-['JetBrains_Mono'] text-[9.5px] uppercase font-bold tracking-wider text-[#ffffff]"
              >
                RADAR TARGET ROSTER ({filteredVectors.length})
              </span>
              <span className="text-[9px] font-['JetBrains_Mono'] text-[#ef4444]">
                CLICK TO LOCK
              </span>
            </div>

            <div className="max-h-36 overflow-y-auto custom-scrollbar space-y-1">
              {filteredVectors.map((v) => (
                <div
                  key={v.id}
                  onClick={() => setSelectedVectorId(v.id)}
                  className={`px-2 py-1.5 border flex items-center justify-between cursor-pointer transition-colors text-[10px] font-['JetBrains_Mono'] ${
                    selectedVector?.id === v.id
                      ? 'bg-[#1a0508] border-[#ef4444] text-[#fee2e2] font-bold'
                      : 'bg-[#000000] border-[#7f1d1d]/40 hover:bg-[#1a0508] text-[#e5e5e5]'
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        v.status === 'NEUTRALIZED'
                          ? 'bg-[#10b981]'
                          : v.severity === 'CRITICAL'
                          ? 'bg-[#ef4444]'
                          : 'bg-[#f59e0b]'
                      }`}
                    />
                    <span className="truncate max-w-[140px]">{v.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[#9ca3af]">
                      {String(v.bearingDeg).padStart(3, '0')}°
                    </span>
                    <span className="font-bold text-[#ef4444]">
                      {Math.round(v.distanceRatio * 100)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
