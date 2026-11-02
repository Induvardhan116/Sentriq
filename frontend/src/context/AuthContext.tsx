import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { User, LoginPayload, RegisterPayload, AuthContextType } from '../types/auth';
import { authLogin, authRegister, authLogout, authGetMe, setMemoryCsrfToken } from '../services/api';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [csrfToken, setCsrfTokenState] = useState<string | null>(null);

  const applyCsrfToken = useCallback((token?: string | null) => {
    if (token) {
      setCsrfTokenState(token);
      setMemoryCsrfToken(token);
    }
  }, []);

  const refreshUser = useCallback(async () => {
    try {
      const currentUser = await authGetMe();
      setUser(currentUser);
      applyCsrfToken(currentUser.csrf_token);
    } catch {
      setUser(null);
      setCsrfTokenState(null);
      setMemoryCsrfToken(null);
    } finally {
      setIsLoading(false);
    }
  }, [applyCsrfToken]);

  // Restore authenticated session on initial application load
  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = async (credentials: LoginPayload) => {
    setIsLoading(true);
    try {
      const response = await authLogin(credentials);
      setUser(response);
      applyCsrfToken(response.csrf_token);
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (payload: RegisterPayload) => {
    setIsLoading(true);
    try {
      const response = await authRegister(payload);
      setUser(response);
      applyCsrfToken(response.csrf_token);
    } finally {
      setIsLoading(false);
    }
  };

  const logout = async () => {
    setIsLoading(true);
    try {
      await authLogout();
    } catch {
      // Ignore network errors on logout to ensure local state clears
    } finally {
      setUser(null);
      setCsrfTokenState(null);
      setMemoryCsrfToken(null);
      setIsLoading(false);
      window.location.hash = '#/login';
    }
  };

  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated: Boolean(user),
    csrfToken,
    login,
    register,
    logout,
    refreshUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
