'use client';

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { useRouter } from 'next/navigation';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Storage keys
const STORAGE_KEYS = {
  TOKEN: 'koba_token',
  REFRESH_TOKEN: 'koba_refresh_token',
  USER: 'koba_user',
  SESSION_ID: 'koba_session_id',
  REMEMBER_ME: 'koba_remember_me',
  TOKEN_EXPIRY: 'koba_token_expiry',
} as const;

// 30 days in milliseconds for "Remember Me"
const REMEMBER_ME_DURATION = 30 * 24 * 60 * 60 * 1000;

interface User {
  id: string;
  email: string;
  username: string;
  role: string;
  permissions: string[];
  created_at: string;
  last_login: string | null;
  is_active: boolean;
  mfa_enabled: boolean;
  tenant_id: string | null;
  is_system_admin: boolean;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  logout: () => Promise<void>;
  register: (email: string, username: string, password: string) => Promise<void>;
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Helper to get storage (localStorage for remember me, sessionStorage otherwise)
function getStorage(rememberMe: boolean): Storage {
  return rememberMe ? localStorage : sessionStorage;
}

// Helper to check if we should use persistent storage
function shouldUsePersistentStorage(): boolean {
  if (typeof window === 'undefined') return false;
  return localStorage.getItem(STORAGE_KEYS.REMEMBER_ME) === 'true';
}

// Helper to get item from appropriate storage
function getStoredItem(key: string): string | null {
  if (typeof window === 'undefined') return null;
  // Check localStorage first (remember me), then sessionStorage
  return localStorage.getItem(key) || sessionStorage.getItem(key);
}

// Helper to set item in appropriate storage
function setStoredItem(key: string, value: string, rememberMe: boolean): void {
  if (typeof window === 'undefined') return;
  const storage = getStorage(rememberMe);
  storage.setItem(key, value);
}

// Helper to remove item from both storages
function removeStoredItem(key: string): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(key);
  sessionStorage.removeItem(key);
}

// Helper to clear all auth data
function clearAllAuthData(): void {
  Object.values(STORAGE_KEYS).forEach(key => removeStoredItem(key));
  // Also clear electron-store backup if running in Electron
  if (typeof window !== 'undefined' && (window as any).kobaDesktop) {
    (window as any).kobaDesktop.clearAuthState().catch(() => {});
  }
}

// Save auth state to electron-store (backup for localStorage)
function saveToElectronStore(data: {
  token: string;
  refreshToken?: string;
  user: string;
  sessionId?: string;
  tokenExpiry?: string;
}): void {
  if (typeof window !== 'undefined' && (window as any).kobaDesktop) {
    (window as any).kobaDesktop.setAuthState(data).catch(() => {});
  }
}

// Restore auth state from electron-store to localStorage
async function restoreFromElectronStore(): Promise<boolean> {
  if (typeof window === 'undefined' || !(window as any).kobaDesktop) return false;
  try {
    const saved = await (window as any).kobaDesktop.getAuthState();
    if (saved?.token) {
      localStorage.setItem(STORAGE_KEYS.TOKEN, saved.token);
      if (saved.refreshToken) localStorage.setItem(STORAGE_KEYS.REFRESH_TOKEN, saved.refreshToken);
      if (saved.user) localStorage.setItem(STORAGE_KEYS.USER, saved.user);
      if (saved.sessionId) localStorage.setItem(STORAGE_KEYS.SESSION_ID, saved.sessionId);
      if (saved.tokenExpiry) localStorage.setItem(STORAGE_KEYS.TOKEN_EXPIRY, saved.tokenExpiry);
      localStorage.setItem(STORAGE_KEYS.REMEMBER_ME, 'true');
      return true;
    }
  } catch { /* ignore */ }
  return false;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function initAuth() {
      // Try restoring from electron-store first (handles localStorage being cleared)
      await restoreFromElectronStore();

      // Now check localStorage (populated from electron-store if needed)
      const storedToken = getStoredItem(STORAGE_KEYS.TOKEN);
      const storedUser = getStoredItem(STORAGE_KEYS.USER);
      const tokenExpiry = getStoredItem(STORAGE_KEYS.TOKEN_EXPIRY);
      const rememberMe = shouldUsePersistentStorage();

      // Check if token has expired for "Remember Me" sessions
      if (tokenExpiry && rememberMe) {
      const expiryTime = parseInt(tokenExpiry, 10);
      if (Date.now() > expiryTime) {
        // Token expired, try to refresh or keep cached data if backend unreachable
        const refreshToken = getStoredItem(STORAGE_KEYS.REFRESH_TOKEN);
        if (refreshToken) {
          refreshAccessToken(refreshToken)
            .then((newToken) => {
              setToken(newToken);
              if (storedUser) {
                try {
                  setUser(JSON.parse(storedUser));
                } catch {
                  clearAllAuthData();
                  setUser(null);
                }
              }
            })
            .catch((err) => {
              // If it's a network error (backend not ready), keep cached data
              if (err instanceof TypeError && err.message.includes('fetch')) {
                console.log('[Koba Auth] Backend unreachable during refresh, using cached session');
                if (storedToken) setToken(storedToken);
                if (storedUser) {
                  try { setUser(JSON.parse(storedUser)); } catch { /* ignore */ }
                }
              } else {
                clearAllAuthData();
              }
            })
            .finally(() => {
              setLoading(false);
            });
          return;
        } else {
          // No refresh token but have cached data - keep using it if backend is down
          if (storedToken && storedUser) {
            setToken(storedToken);
            try { setUser(JSON.parse(storedUser)); } catch { /* ignore */ }
          } else {
            clearAllAuthData();
          }
          setLoading(false);
          return;
        }
      }
    }

    if (storedToken && storedUser) {
      setToken(storedToken);
      try {
        setUser(JSON.parse(storedUser));
      } catch {
        clearAllAuthData();
        setUser(null);
        setLoading(false);
        return;
      }

      // Verify token is still valid (but don't wipe data on network errors)
      verifyToken(storedToken).then((result) => {
        if (result === 'valid') {
          // Token verified, user data already updated by verifyToken
        } else if (result === 'unreachable') {
          // Backend not reachable - keep using cached user data
          // This happens when the Docker container is still starting up
          console.log('[Koba Auth] Backend unreachable, using cached session');
        } else {
          // Token is genuinely invalid (server returned 401/403)
          const refreshToken = getStoredItem(STORAGE_KEYS.REFRESH_TOKEN);
          if (rememberMe && refreshToken) {
            return refreshAccessToken(refreshToken)
              .then((newToken) => {
                setToken(newToken);
              })
              .catch(() => {
                clearAllAuthData();
                setToken(null);
                setUser(null);
              });
          } else {
            clearAllAuthData();
            setToken(null);
            setUser(null);
          }
        }
      }).finally(() => {
        setLoading(false);
      });
    } else {
      setLoading(false);
    }
    }
    initAuth();
  }, []);

  const refreshAccessToken = async (refreshToken: string): Promise<string> => {
    const response = await fetch(`${API_BASE}/v1/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) {
      throw new Error('Failed to refresh token');
    }

    const data = await response.json();
    const rememberMe = shouldUsePersistentStorage();

    setStoredItem(STORAGE_KEYS.TOKEN, data.access_token, rememberMe);
    if (data.refresh_token) {
      setStoredItem(STORAGE_KEYS.REFRESH_TOKEN, data.refresh_token, rememberMe);
    }

    // Update expiry time
    const expiryTime = Date.now() + REMEMBER_ME_DURATION;
    setStoredItem(STORAGE_KEYS.TOKEN_EXPIRY, expiryTime.toString(), rememberMe);

    return data.access_token;
  };

  const verifyToken = async (accessToken: string): Promise<'valid' | 'invalid' | 'unreachable'> => {
    try {
      const response = await fetch(`${API_BASE}/v1/auth/me`, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        // Server responded with an error - token is genuinely invalid
        return 'invalid';
      }

      const userData = await response.json();
      setUser(userData);

      const rememberMe = shouldUsePersistentStorage();
      setStoredItem(STORAGE_KEYS.USER, JSON.stringify(userData), rememberMe);
      return 'valid';
    } catch {
      // Network error - backend not reachable (still starting up, etc.)
      // Do NOT clear auth data - keep the user logged in with cached data
      return 'unreachable';
    }
  };

  const login = async (email: string, password: string, rememberMe: boolean = false) => {
    const response = await fetch(`${API_BASE}/v1/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Login failed' }));
      throw new Error(error.detail || 'Login failed');
    }

    const data = await response.json();

    setToken(data.access_token);
    setUser(data.user);

    // Store the remember me preference first
    if (rememberMe) {
      localStorage.setItem(STORAGE_KEYS.REMEMBER_ME, 'true');
    } else {
      localStorage.removeItem(STORAGE_KEYS.REMEMBER_ME);
    }

    // Store auth data in appropriate storage
    setStoredItem(STORAGE_KEYS.TOKEN, data.access_token, rememberMe);
    setStoredItem(STORAGE_KEYS.REFRESH_TOKEN, data.refresh_token, rememberMe);
    setStoredItem(STORAGE_KEYS.USER, JSON.stringify(data.user), rememberMe);

    if (data.session_id) {
      setStoredItem(STORAGE_KEYS.SESSION_ID, data.session_id, rememberMe);
    }

    // Set expiry time for remember me sessions
    const tokenExpiry = rememberMe ? (Date.now() + REMEMBER_ME_DURATION).toString() : '';
    if (rememberMe) {
      setStoredItem(STORAGE_KEYS.TOKEN_EXPIRY, tokenExpiry, true);
    }

    // Backup to electron-store (survives localStorage clearing between app restarts)
    saveToElectronStore({
      token: data.access_token,
      refreshToken: data.refresh_token,
      user: JSON.stringify(data.user),
      sessionId: data.session_id || '',
      tokenExpiry,
    });
  };

  const logout = async () => {
    const sessionId = getStoredItem(STORAGE_KEYS.SESSION_ID);

    if (token) {
      try {
        await fetch(`${API_BASE}/v1/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ session_id: sessionId }),
        });
      } catch (e) {
        // Ignore logout errors
      }
    }

    setToken(null);
    setUser(null);
    clearAllAuthData();
  };

  const register = async (email: string, username: string, password: string) => {
    const response = await fetch(`${API_BASE}/v1/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, username, password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Registration failed' }));
      throw new Error(error.detail || 'Registration failed');
    }

    // Auto-login after registration (without remember me)
    await login(email, password, false);
  };

  const hasPermission = useCallback((permission: string): boolean => {
    if (!user) return false;
    return user.permissions?.includes(permission) || user.role === 'super_admin';
  }, [user]);

  return (
    <AuthContext.Provider value={{ user, token, loading, login, logout, register, hasPermission }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export function useRequireAuth() {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.push('/login');
    }
  }, [user, loading, router]);

  return { user, loading };
}
