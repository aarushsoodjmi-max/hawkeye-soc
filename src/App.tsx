/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useCallback } from 'react';
import {
  NavTab,
  StreamMetrics,
  IncidentRecord,
  ThemeMode,
} from './types';
import { useSoc } from './context/SocContext';
import { useAuth } from './context/AuthContext';
import { Sidebar } from './components/Sidebar';
import { TopHeader } from './components/TopHeader';
import { LiveEventStream } from './components/LiveEventStream';
import { BottomStatusBar } from './components/BottomStatusBar';
import { OverviewView } from './components/OverviewView';
import { IncidentsView } from './components/IncidentsView';
import { IncidentInvestigationView } from './components/IncidentInvestigationView';
import { DecisionCenterView } from './components/DecisionCenterView';
import { PlaybookEngineView } from './components/PlaybookEngineView';
import { Asset360View } from './components/Asset360View';
import { KnowledgeGraphView } from './components/KnowledgeGraphView';
import { ReportingView } from './components/ReportingView';
import { SimulatorView } from './components/SimulatorView';
import { TacticalModuleView } from './components/TacticalModuleView';
import { RunQueryModal } from './components/RunQueryModal';
import { DeployContainmentModal } from './components/DeployContainmentModal';
import { ContainmentModeBanner } from './components/ContainmentModeBanner';
import { ApprovalGateModal } from './components/ApprovalGateModal';
import { LoginModal } from './components/LoginModal';
import { ToastContainer } from './components/ToastContainer';
import { SplashScreen } from './components/SplashScreen';
import { AnimatePresence } from 'motion/react';

export default function App() {
  const {
    events,
    alerts,
    assets,
    incidents,
    activeIncidentId,
    setActiveIncidentId,
    activeIncident,
    containmentActive,
    setContainmentActive,
    metrics,
    dashboardMetrics,
    isStreaming,
    toggleStreaming,
    clearEventsBuffer,
    selectedEventId,
    setSelectedEventId,
    blockIp,
    quarantineHost,
    correlateEventToIncident,
    deployContainment,
    backendStatus,
    pendingApproval,
    approvePendingAction,
    rejectPendingAction,
  } = useSoc();

  const { canExecuteActions, isAuthenticated } = useAuth();

  // Navigation
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [incidentSubMode, setIncidentSubMode] = useState<'dossier' | 'triage_list'>('dossier');

  // Theme (dark or light)
  const [theme, setTheme] = useState<ThemeMode>('dark');
  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  }, []);

  // Splash Screen at start
  const [showSplash, setShowSplash] = useState(true);
  const handleReplaySplash = useCallback(() => {
    setShowSplash(true);
  }, []);

  // Modals
  const [isQueryModalOpen, setIsQueryModalOpen] = useState(false);
  const [isContainmentModalOpen, setIsContainmentModalOpen] = useState(false);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  React.useEffect(() => { if (!isAuthenticated) setIsLoginModalOpen(true); }, [isAuthenticated]);

  // Search
  const [searchQuery, setSearchQuery] = useState('');

  const handleViewIncident = useCallback((incidentId: string) => {
    setActiveIncidentId(incidentId);
    setActiveTab('incidents');
  }, [setActiveIncidentId]);

  const handleDeployContainment = useCallback(
    (options: {
      isolateHosts: boolean;
      revokeTokens: boolean;
      bgpBlackhole: boolean;
      killProcesses: boolean;
    }) => {
      void deployContainment(options);
      setIsContainmentModalOpen(false);
    },
    [deployContainment]
  );

  // Simulator actions are explicit backend operations. The frontend never
  // manufactures telemetry records.
  const { loadScenario } = useSoc();
  const handleInjectAttack = useCallback(
    (type: 'mfa_replay' | 'lsass_dump' | 'c2_beacon' | 'dns_exfil' | 'iam_escalation') => {
      const scenarioByType: Record<typeof type, string> = {
        mfa_replay: 'credential_theft',
        lsass_dump: 'malware',
        c2_beacon: 'ransomware',
        dns_exfil: 'phishing',
        iam_escalation: 'insider_threat',
      };
      void loadScenario(scenarioByType[type]);
      setActiveTab('live_events');
    },
    [loadScenario]
  );

  return (
    <div
      className={`h-screen w-screen font-['Geist'] overflow-hidden select-none transition-colors duration-200 ${
        theme === 'light'
          ? 'theme-light bg-[#f4f5f8] text-[#0f172a]'
          : 'bg-[#000000] text-[#f3f0f3]'
      }`}
    >
      {/* TACTICAL BOOT SPLASH SCREEN */}
      <AnimatePresence>
        {showSplash && (
          <SplashScreen onComplete={() => setShowSplash(false)} />
        )}
      </AnimatePresence>

      {/* SIDE NAVIGATION (Fixed Left w-60) */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        incidentCount={incidents.length}
        containmentActive={containmentActive}
        onToggleContainmentModal={() => setIsContainmentModalOpen(true)}
        theme={theme}
        onReplaySplash={handleReplaySplash}
      />

      {/* TOP HEADER (Fixed Top left-60 right-0 h-14) */}
      <TopHeader
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onOpenQueryModal={() => setIsQueryModalOpen(true)}
        onOpenContainmentModal={() => setIsContainmentModalOpen(true)}
        epsRate={metrics.ingestionRate}
        latencyMs={undefined}
        theme={theme}
        onToggleTheme={toggleTheme}
        onReplaySplash={handleReplaySplash}
        onOpenLoginModal={() => setIsLoginModalOpen(true)}
      />

      {/* ACTIVE CONTAINMENT BANNER */}
      <ContainmentModeBanner
        isActive={containmentActive}
        onRelease={() => setContainmentActive(false)}
        onViewContainmentDetails={() => setIsContainmentModalOpen(true)}
        theme={theme}
      />

      {/* MAIN VIEWPORT CANVAS */}
      <main
        className={`fixed left-60 right-0 bottom-7 overflow-y-auto custom-scrollbar transition-all ${
          containmentActive ? 'top-21' : 'top-14'
        }`}
      >
        {activeTab === 'overview' && (
          <OverviewView
            metrics={metrics}
            dashboardMetrics={dashboardMetrics}
            incidents={incidents}
            events={events}
            onSelectIncident={handleViewIncident}
            onNavigateToLive={() => setActiveTab('live_events')}
            theme={theme}
          />
        )}

        {activeTab === 'live_events' && (
          <LiveEventStream
            events={events}
            selectedEventId={selectedEventId}
            onSelectEvent={setSelectedEventId}
            onBlockIp={blockIp}
            onQuarantineHost={quarantineHost}
            onCorrelateIncident={correlateEventToIncident}
            onViewIncident={handleViewIncident}
            onClearBuffer={clearEventsBuffer}
            isStreaming={isStreaming}
            onToggleStreaming={toggleStreaming}
            metrics={metrics}
            searchFilter={searchQuery}
            theme={theme}
          />
        )}

        {activeTab === 'incidents' && (
          <div className="w-full flex flex-col">
            {/* View Mode Toggle Bar */}
            <div
              className={`p-2 border-b flex items-center justify-between px-6 font-['JetBrains_Mono'] text-[11px] ${
                theme === 'light' ? 'bg-[#f1f5f9] border-[#cbd5e1]' : 'bg-[#080203] border-[#7f1d1d]/60'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="opacity-70 uppercase font-bold">VIEW MODE:</span>
                <button
                  type="button"
                  onClick={() => setIncidentSubMode('dossier')}
                  className={`px-2.5 py-0.5 rounded font-bold transition-all border ${
                    incidentSubMode === 'dossier'
                      ? 'border-[#ef4444] bg-[#ef4444] text-white'
                      : 'border-inherit text-current opacity-70 hover:opacity-100'
                  }`}
                >
                  Investigation Dossier & AI
                </button>
                <button
                  type="button"
                  onClick={() => setIncidentSubMode('triage_list')}
                  className={`px-2.5 py-0.5 rounded font-bold transition-all border ${
                    incidentSubMode === 'triage_list'
                      ? 'border-[#ef4444] bg-[#ef4444] text-white'
                      : 'border-inherit text-current opacity-70 hover:opacity-100'
                  }`}
                >
                  Multi-Incident Split Triage
                </button>
              </div>

              <span className="text-[#ef4444] font-bold">
                INCIDENT REF: {activeIncidentId}
              </span>
            </div>

            {incidentSubMode === 'dossier' ? (
              <IncidentInvestigationView theme={theme} />
            ) : (
              <IncidentsView
                incidents={incidents}
                activeIncidentId={activeIncidentId}
                onSelectIncident={setActiveIncidentId}
                onNavigateToLive={() => setActiveTab('live_events')}
                theme={theme}
              />
            )}
          </div>
        )}

        {activeTab === 'decision_center' && (
          <DecisionCenterView theme={theme} />
        )}

        {activeTab === 'playbooks' && (
          <PlaybookEngineView theme={theme} />
        )}

        {activeTab === 'assets' && (
          <Asset360View theme={theme} />
        )}

        {activeTab === 'knowledge_graph' && (
          <KnowledgeGraphView theme={theme} />
        )}

        {activeTab === 'reports' && (
          <ReportingView theme={theme} />
        )}

        {activeTab === 'simulator' && (
          <SimulatorView
            onInjectAttack={handleInjectAttack}
            onSpikeIngestion={() => void loadScenario('malware')}
            onResetBuffer={clearEventsBuffer}
            onNavigateToLive={() => setActiveTab('live_events')}
            theme={theme}
          />
        )}

        {/* Tactical Module for backend-backed navigation items */}
        {activeTab !== 'overview' &&
          activeTab !== 'live_events' &&
          activeTab !== 'incidents' &&
          activeTab !== 'decision_center' &&
          activeTab !== 'playbooks' &&
          activeTab !== 'assets' &&
          activeTab !== 'knowledge_graph' &&
          activeTab !== 'reports' &&
          activeTab !== 'simulator' && (
            <TacticalModuleView
              tab={activeTab}
              onNavigateToLive={() => setActiveTab('live_events')}
              theme={theme}
              alerts={alerts}
              incidents={incidents}
              assets={assets}
              events={events}
            />
          )}
      </main>

      {/* BOTTOM STATUS BAR (Fixed Bottom left-60 right-0 h-7) */}
      <BottomStatusBar
        onlineNodes={metrics.activeLogSources}
        totalNodes={metrics.totalLogSources}
        bufferPercent={metrics.bufferPercent}
        bufferUsedGB={metrics.bufferUsedGB}
        backendStatus={backendStatus}
        theme={theme}
      />

      {/* TOAST NOTIFICATION CONTAINER */}
      <ToastContainer theme={theme} />

      {/* HUMAN-IN-THE-LOOP APPROVAL GATE MODAL */}
      <ApprovalGateModal
        isOpen={Boolean(pendingApproval)}
        request={pendingApproval}
        onConfirm={() => approvePendingAction()}
        onCancel={() => rejectPendingAction()}
      />

      {/* AUTH & WORKSPACE RBAC LOGIN MODAL */}
      <LoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
      />

      {/* RUN QUERY MODAL */}
      <RunQueryModal
        isOpen={isQueryModalOpen}
        onClose={() => setIsQueryModalOpen(false)}
        onRunQuery={(q) => {
          if (q.includes('source=')) {
            const match = q.match(/source="([^"]+)"/);
            if (match && match[1]) {
              setSearchQuery(match[1]);
            }
          }
          setIsQueryModalOpen(false);
          setActiveTab('live_events');
        }}
        events={events}
        theme={theme}
      />

      {/* DEPLOY CONTAINMENT MODAL */}
      <DeployContainmentModal
        isOpen={isContainmentModalOpen}
        onClose={() => setIsContainmentModalOpen(false)}
        onDeploy={handleDeployContainment}
        theme={theme}
      />
    </div>
  );
}
