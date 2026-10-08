/**
 * HawkEye SOC — Authentication & RBAC Context
 * ============================================
 * Handles JWT authentication, token decoding, workspace switching,
 * and role-based permissions (admin, operator, analyst, viewer).
 */

import React, { createContext, useContext, useState, useEffect, useMemo, ReactNode } from 'react';
import { Principal, Role, WorkspaceId } from '../types';
import { api } from '../services/api';
import { wsClient } from '../services/websocket';

export interface AuthContextType {
  user: Principal | null;
  principal: Principal | null;
  token: string | null;
  workspace: WorkspaceId;
  role: Role;
  isAuthenticated: boolean;
  isAuthModalOpen: boolean;
  setIsAuthModalOpen: (open: boolean) => void;
  login: (username: string, password: string, workspace?: WorkspaceId) => Promise<void>;
  logout: () => void;
  switchWorkspace: (workspace: WorkspaceId) => void;
  setWorkspace: (workspace: WorkspaceId) => void;
  switchRole: (role: Role) => void;
  // RBAC Permission Helpers
  canExecuteActions: boolean;
  canApprovePlaybooks: boolean;
  canRunSimulations: boolean;
  canRequestAi: boolean;
  isReadOnly: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => api.getToken());
  // Do NOT initialize as authenticated operator before login when connected mode is expected
  const [user, setUser] = useState<Principal | null>(() => {
    const decoded = api.decodePrincipal();
    if (decoded && (!decoded.exp || decoded.exp > Date.now() / 1000)) {
      return decoded;
    }
    return null;
  });
  const [workspace, setWorkspace] = useState<WorkspaceId>(() => api.getWorkspace() || 'default');
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);

  // Sync token on mount and handle unauthorized events
  useEffect(() => {
    api.setOnUnauthorized(() => {
      logout();
      setIsAuthModalOpen(true);
    });

    if (token) {
      wsClient.connect(token);
    }
  }, [token]);

  // FAIL-CLOSED Login: A failed login MUST remain a failed login
  const login = async (username: string, password: string, selectedWorkspace: WorkspaceId = 'default') => {
    const res = await api.login(username, password, selectedWorkspace);
    setToken(res.access_token);
    const decoded = api.decodePrincipal();
    if (!decoded) {
      api.logout();
      setToken(null);
      setUser(null);
      throw new Error('Backend returned an invalid JWT');
    }
    if (decoded.workspace !== selectedWorkspace) {
      api.logout();
      setToken(null);
      setUser(null);
      throw new Error('Authenticated workspace does not match the requested workspace');
    }
    // Workspace comes from the authenticated backend identity (JWT claim),
    // never from client input or storage.
    setWorkspace(decoded.workspace);
    setUser(decoded);
    wsClient.connect(res.access_token);
    setIsAuthModalOpen(false);
  };

  const logout = () => {
    api.logout();
    wsClient.disconnect();
    setToken(null);
    setUser(null);
  };

  const switchWorkspace = (newWorkspace: WorkspaceId) => {
    if (user && newWorkspace !== user.workspace) {
      setIsAuthModalOpen(true);
      return;
    }
    api.setWorkspace(newWorkspace);
    setWorkspace(newWorkspace);
  };

  const switchRole = (_newRole: Role) => {
    // Role is an immutable JWT claim. It can only change through backend authentication.
    setIsAuthModalOpen(true);
  };

  const role = user?.role || 'viewer';

  // RBAC Matrix — mirrors backend authorization exactly (backend stays authoritative):
  //   canApprovePlaybooks  = admin + analyst + operator
  //   canExecuteActions    = admin + analyst + operator
  //   canRunSimulations    = admin + analyst + operator
  //   canRequestAi         = admin + analyst   (backend /api/ai/analyze)
  const canExecuteActions = !!user && ['admin', 'analyst', 'operator'].includes(role);
  const canApprovePlaybooks = !!user && ['admin', 'analyst', 'operator'].includes(role);
  const canRunSimulations = !!user && ['admin', 'analyst', 'operator'].includes(role);
  const canRequestAi = !!user && (role === 'admin' || role === 'analyst');
  const isReadOnly = !user || role === 'viewer';

  const value = useMemo(
    () => ({
      user,
      principal: user,
      token,
      workspace,
      setWorkspace: switchWorkspace,
      role,
      isAuthenticated: !!user,
      isAuthModalOpen,
      setIsAuthModalOpen,
      login,
      logout,
      switchWorkspace,
      switchRole,
      canExecuteActions,
      canApprovePlaybooks,
      canRunSimulations,
      canRequestAi,
      isReadOnly,
    }),
    [user, token, workspace, role, isAuthModalOpen, canExecuteActions, canApprovePlaybooks, canRunSimulations, canRequestAi, isReadOnly]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
};
