import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { Role, ThemeMode, WorkspaceId } from '../types';
import { HawkEyeLogo } from './HawkEyeLogo';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  theme?: ThemeMode;
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose, theme = 'dark' }) => {
  const { user, login, logout, workspace, switchWorkspace } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [selectedWorkspace, setSelectedWorkspace] = useState<WorkspaceId>(workspace);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen) return null;
  const isLight = theme === 'light';

  const handleManualLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) {
      setErrorMessage('Please enter both username and password.');
      return;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      await login(username.trim(), password, selectedWorkspace);
      onClose();
    } catch (err: unknown) {
      setErrorMessage((err as Error)?.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      id="login-modal-overlay"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm select-none"
    >
      <div
        className={`w-full max-w-lg border rounded-lg overflow-hidden shadow-2xl transition-colors duration-200 ${
          isLight
            ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]'
            : 'bg-[#050102] border-[#7f1d1d]/80 text-[#f3f4f6] shadow-[0_0_40px_rgba(239,68,68,0.2)]'
        }`}
      >
        {/* Modal Header */}
        <div
          className={`p-4 border-b flex items-center justify-between ${
            isLight ? 'bg-[#f8fafc] border-[#e2e8f0]' : 'bg-[#000000] border-[#7f1d1d]/60'
          }`}
        >
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded border border-[#ef4444] bg-black p-0.5 flex items-center justify-center">
              <HawkEyeLogo variant="badge" animated={false} showText={false} className="w-full h-full" />
            </div>
            <div>
              <h2 className="font-['Space_Grotesk'] text-[16px] font-bold tracking-tight">
                HawkEye SOC Authentication
              </h2>
              <p className="font-['JetBrains_Mono'] text-[10px] text-[#ef4444]">
                JWT BEARER // RBAC-ISOLATED WORKSPACE CONSOLE
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-current opacity-70 hover:opacity-100 transition-opacity"
          >
            <span className="material-symbols-outlined text-[18px]">close</span>
          </button>
        </div>

        <div className="p-5 flex flex-col gap-4">
          {/* Current Session Overview */}
          {user && (
            <div
              className={`p-3 border rounded text-[11px] font-['JetBrains_Mono'] flex items-center justify-between ${
                isLight ? 'bg-[#f1f5f9] border-[#cbd5e1]' : 'bg-[#120305] border-[#7f1d1d]/50'
              }`}
            >
              <div>
                <span className="opacity-60">AUTHENTICATED AS: </span>
                <span className="font-bold text-[#ef4444]">{user.sub}</span>
                <div className="mt-0.5 flex gap-2">
                  <span>ROLE: <strong className="uppercase">{user.role}</strong></span>
                  <span>|</span>
                  <span>WORKSPACE: <strong>{user.workspace}</strong></span>
                </div>
              </div>
              <button
                type="button"
                onClick={logout}
                className="px-2.5 py-1 border border-[#dc2626] text-[#dc2626] hover:bg-[#dc2626] hover:text-white transition-colors rounded text-[10px] font-bold"
              >
                LOGOUT
              </button>
            </div>
          )}

          {/* Credentials Form for Live Backend Authentication */}
          <form onSubmit={handleManualLogin} className="flex flex-col gap-3">
            <span className="font-['JetBrains_Mono'] text-[10px] uppercase font-bold tracking-wider opacity-80">
              Live Backend Credentials & Workspace Selection:
            </span>

            {/* Workspace Selector */}
            <div className="flex flex-col gap-1">
              <label className="font-['JetBrains_Mono'] text-[10px] opacity-70">
                TENANT WORKSPACE
              </label>
              <select
                value={selectedWorkspace}
                onChange={(e) => {
                  setSelectedWorkspace(e.target.value);
                  switchWorkspace(e.target.value);
                }}
                className={`h-8 px-2 border font-['JetBrains_Mono'] text-[11px] rounded ${
                  isLight
                    ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]'
                    : 'bg-[#050102] border-[#7f1d1d]/60 text-white'
                }`}
              >
                <option value="default">default (Enterprise Core Operations)</option>
                <option value="finance-sec">finance-sec (PCI-DSS Financial Subnet)</option>
                <option value="cloud-infra">cloud-infra (AWS / Kubernetes Workloads)</option>
                <option value="secops-core">secops-core (Adversary Triage & Red Team)</option>
              </select>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div className="flex flex-col gap-1">
                <label className="font-['JetBrains_Mono'] text-[10px] opacity-70">USERNAME / UPN</label>
                <input
                  type="text"
                  autoComplete="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className={`h-8 px-2 border font-['JetBrains_Mono'] text-[11px] rounded ${
                    isLight
                      ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]'
                      : 'bg-[#050102] border-[#7f1d1d]/60 text-white'
                  }`}
                  placeholder="Enter username or email"
                />
              </div>
              <div className="flex flex-col gap-1">
                <label className="font-['JetBrains_Mono'] text-[10px] opacity-70">PASSWORD</label>
                <input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={`h-8 px-2 border font-['JetBrains_Mono'] text-[11px] rounded ${
                    isLight
                      ? 'bg-[#ffffff] border-[#cbd5e1] text-[#0f172a]'
                      : 'bg-[#050102] border-[#7f1d1d]/60 text-white'
                  }`}
                  placeholder="••••••••"
                />
              </div>
            </div>

            {errorMessage && (
              <div className="p-2 border border-[#ef4444] bg-[#ef4444]/15 rounded text-[#ef4444] text-[11px] font-['JetBrains_Mono']">
                {errorMessage}
              </div>
            )}

            <div className="flex justify-end gap-2 mt-2">
              <button
                type="button"
                onClick={onClose}
                className={`h-8 px-3 border font-['JetBrains_Mono'] text-[11px] rounded ${
                  isLight ? 'border-[#cbd5e1] text-[#475569]' : 'border-[#7f1d1d]/60 text-[#d1d5db]'
                }`}
              >
                Close
              </button>
              <button
                type="submit"
                disabled={isLoading}
                className="h-8 px-4 border border-[#dc2626] bg-[#dc2626] hover:bg-[#b91c1c] text-white font-['JetBrains_Mono'] text-[11px] font-bold rounded flex items-center gap-1.5 transition-colors"
              >
                {isLoading ? (
                  <>
                    <span className="material-symbols-outlined text-[14px] animate-spin">refresh</span>
                    Authenticating...
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined text-[14px]">vpn_key</span>
                    Authenticate Session
                  </>
                )}
              </button>
            </div>
          </form>

        </div>
      </div>
    </div>
  );
};
