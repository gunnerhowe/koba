'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import AppShell from '@/components/AppShell';
import { useAuth } from '@/lib/auth';
import { API_BASE } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import ToastContainer from '@/components/Toast';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

interface Settings {
  jwt_ttl: number;
  default_policy: string;
  tripwire_enabled: boolean;
  sandbox_enabled: boolean;
  min_commitment_delay: number;
}

export default function SettingsPage() {
  const router = useRouter();
  const { user, token, loading: authLoading, hasPermission } = useAuth();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<'general' | 'security' | 'profile'>('general');
  const { toasts, showToast, dismissToast } = useToast();

  // Profile state
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [passwordSuccess, setPasswordSuccess] = useState(false);

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  useEffect(() => {
    if (!user) return;

    // If user doesn't have settings permission, stop loading
    if (!hasPermission('settings:read')) {
      setLoading(false);
      return;
    }

    async function loadSettings() {
      try {
        const res = await fetch(`${API_BASE}/v1/settings`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          setSettings(await res.json());
        } else if (res.status === 403) {
          // Permission denied from backend - this is expected for non-admin users
          console.log('Settings access denied by server');
        }
      } catch (e) {
        console.error('Failed to load settings', e);
      } finally {
        setLoading(false);
      }
    }

    loadSettings();
  }, [user, token, hasPermission]);

  const saveSettings = async () => {
    if (!settings) return;
    setSaving(true);

    try {
      const res = await fetch(`${API_BASE}/v1/settings`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(settings),
      });

      if (res.ok) {
        showToast('Settings saved successfully', 'success');
      } else {
        showToast('Failed to save settings', 'error');
      }
    } catch (e) {
      console.error('Failed to save settings', e);
      showToast('Failed to save settings', 'error');
    } finally {
      setSaving(false);
    }
  };

  const changePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPasswordError('');
    setPasswordSuccess(false);

    if (newPassword !== confirmPassword) {
      setPasswordError('Passwords do not match');
      return;
    }

    if (newPassword.length < 6) {
      setPasswordError('Password must be at least 6 characters');
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/v1/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          old_password: oldPassword,
          new_password: newPassword,
        }),
      });

      if (res.ok) {
        setPasswordSuccess(true);
        setOldPassword('');
        setNewPassword('');
        setConfirmPassword('');
      } else {
        const error = await res.json();
        setPasswordError(error.detail || 'Failed to change password');
      }
    } catch (e) {
      setPasswordError('Failed to change password');
    }
  };

  if (authLoading || !user) {
    return (
      <div className="min-h-screen bg-koba-bg flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-koba-accent/30 border-t-koba-accent rounded-full animate-spin" />
          <p className="text-koba-text-secondary text-sm">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <AppShell>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="max-w-4xl mx-auto">
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold text-koba-text">Settings</h1>
            <HelpButton content={helpContent.settings} />
          </div>
          <p className="text-koba-text-secondary mt-1">Configure system settings and your profile</p>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6" role="tablist">
          {(['general', 'security', 'profile'] as const).map((tab) => (
            <button
              key={tab}
              role="tab"
              aria-selected={activeTab === tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-xl font-medium transition-all ${
                activeTab === tab
                  ? 'bg-koba-accent text-white shadow-glow-sm'
                  : 'bg-koba-bg-card text-koba-text-secondary hover:text-koba-text border border-koba-border'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* General Settings */}
        {activeTab === 'general' && (
          <div className="koba-card">
            {!hasPermission('settings:read') ? (
              <div className="text-center py-8">
                <div className="w-16 h-16 mx-auto mb-4 bg-koba-warning-muted rounded-2xl flex items-center justify-center">
                  <svg className="w-8 h-8 text-koba-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-koba-text mb-2">Settings Access Required</h3>
                <p className="text-koba-text-secondary max-w-md mx-auto">
                  System settings require administrative privileges. You can still manage your profile and change your password in the Profile tab.
                </p>
              </div>
            ) : loading ? (
              <div className="space-y-4">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-12 bg-koba-bg-elevated rounded-xl animate-shimmer" />
                ))}
              </div>
            ) : settings ? (
              <div className="space-y-6">
                <div>
                  <label className="koba-label">Default Policy Bundle</label>
                  <input
                    type="text"
                    value={settings.default_policy || ''}
                    onChange={(e) =>
                      setSettings({ ...settings, default_policy: e.target.value })
                    }
                    className="koba-input"
                    disabled={!hasPermission('settings:write')}
                  />
                </div>

                <div>
                  <label className="koba-label">Minimum Commitment Delay (seconds)</label>
                  <input
                    type="number"
                    value={settings.min_commitment_delay || 60}
                    onChange={(e) =>
                      setSettings({ ...settings, min_commitment_delay: parseInt(e.target.value) })
                    }
                    className="koba-input"
                    disabled={!hasPermission('settings:write')}
                  />
                  <p className="koba-label-hint mt-1">
                    How long before a committed action can be revealed
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-6">
                  <label className="flex items-center gap-3 cursor-pointer group">
                    <input
                      type="checkbox"
                      checked={settings.tripwire_enabled}
                      onChange={(e) =>
                        setSettings({ ...settings, tripwire_enabled: e.target.checked })
                      }
                      className="w-4 h-4 rounded border-koba-border bg-koba-bg-card text-koba-accent focus:ring-koba-accent focus:ring-offset-0 focus:ring-2"
                      disabled={!hasPermission('settings:write')}
                    />
                    <span className="text-koba-text-secondary group-hover:text-koba-text transition-colors">Behavior Monitoring</span>
                  </label>

                  <label className="flex items-center gap-3 cursor-pointer group">
                    <input
                      type="checkbox"
                      checked={settings.sandbox_enabled}
                      onChange={(e) =>
                        setSettings({ ...settings, sandbox_enabled: e.target.checked })
                      }
                      className="w-4 h-4 rounded border-koba-border bg-koba-bg-card text-koba-accent focus:ring-koba-accent focus:ring-offset-0 focus:ring-2"
                      disabled={!hasPermission('settings:write')}
                    />
                    <span className="text-koba-text-secondary group-hover:text-koba-text transition-colors">Sandbox Execution</span>
                  </label>
                </div>

                {hasPermission('settings:write') && (
                  <button
                    onClick={saveSettings}
                    disabled={saving}
                    className="koba-btn koba-btn-primary"
                  >
                    {saving ? (
                      <>
                        <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        Saving...
                      </>
                    ) : (
                      'Save Settings'
                    )}
                  </button>
                )}
              </div>
            ) : (
              <div className="text-center py-8">
                <p className="text-koba-text-secondary">Failed to load settings.</p>
              </div>
            )}
          </div>
        )}

        {/* Security Settings */}
        {activeTab === 'security' && (
          <div className="koba-card">
            <h3 className="text-lg font-medium text-koba-text mb-4">Security Features</h3>
            <div className="space-y-3">
              <div className="p-4 bg-koba-bg-elevated rounded-xl border border-koba-border">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-koba-text font-medium">Cryptographic Receipts</span>
                  <span className="koba-badge koba-badge-success">ENABLED</span>
                </div>
                <p className="text-koba-text-secondary text-sm">
                  All actions produce Ed25519 signed receipts with Merkle proof inclusion.
                </p>
              </div>

              <div className="p-4 bg-koba-bg-elevated rounded-xl border border-koba-border">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-koba-text font-medium">Capability Tokens</span>
                  <span className="koba-badge koba-badge-success">ENABLED</span>
                </div>
                <p className="text-koba-text-secondary text-sm">
                  Cryptographically unforgeable tokens govern agent capabilities — your permissions, enforced.
                </p>
              </div>

              <div className="p-4 bg-koba-bg-elevated rounded-xl border border-koba-border">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-koba-text font-medium">Commitment Scheme</span>
                  <span className="koba-badge koba-badge-success">ENABLED</span>
                </div>
                <p className="text-koba-text-secondary text-sm">
                  Agents commit to actions before execution, with a built-in review period for your oversight.
                </p>
              </div>

              <div className="p-4 bg-koba-bg-elevated rounded-xl border border-koba-border">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-koba-text font-medium">Default-Deny Policy</span>
                  <span className="koba-badge koba-badge-success">ENABLED</span>
                </div>
                <p className="text-koba-text-secondary text-sm">
                  All actions are denied by default unless explicitly allowed by policy rules.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Profile Settings */}
        {activeTab === 'profile' && (
          <div className="space-y-6">
            {/* User Info */}
            <div className="koba-card">
              <h3 className="text-lg font-medium text-koba-text mb-4">Profile Information</h3>
              <div className="flex items-center gap-6">
                <div className="w-20 h-20 bg-koba-accent-muted rounded-full flex items-center justify-center">
                  <span className="text-3xl font-bold text-koba-accent">
                    {user.username.charAt(0).toUpperCase()}
                  </span>
                </div>
                <div>
                  <h4 className="text-xl font-medium text-koba-text">{user.username}</h4>
                  <p className="text-koba-text-secondary">{user.email}</p>
                  <span className={`koba-badge mt-2 ${
                    user.role === 'super_admin'
                      ? 'bg-koba-accent-muted text-koba-accent'
                      : user.role === 'admin'
                      ? 'bg-koba-accent-muted text-koba-accent-light'
                      : 'bg-koba-bg-elevated text-koba-text-muted'
                  }`}>
                    {user.role.replace('_', ' ').toUpperCase()}
                  </span>
                </div>
              </div>
            </div>

            {/* Change Password */}
            <div className="koba-card">
              <h3 className="text-lg font-medium text-koba-text mb-4">Change Password</h3>

              {passwordSuccess && (
                <div className="mb-4 p-4 bg-koba-success-muted border border-koba-success/30 rounded-xl flex items-center gap-3">
                  <svg className="w-5 h-5 text-koba-success flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  <p className="text-koba-success text-sm">Password changed successfully!</p>
                </div>
              )}

              {passwordError && (
                <div className="mb-4 p-4 bg-koba-danger-muted border border-koba-danger/30 rounded-xl flex items-center gap-3">
                  <svg className="w-5 h-5 text-koba-danger flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <p className="text-koba-danger text-sm">{passwordError}</p>
                </div>
              )}

              <form onSubmit={changePassword} className="space-y-5">
                <div>
                  <label className="koba-label">Current Password</label>
                  <input
                    type="password"
                    value={oldPassword}
                    onChange={(e) => setOldPassword(e.target.value)}
                    className="koba-input"
                    required
                    autoComplete="current-password"
                  />
                </div>

                <div>
                  <label className="koba-label">New Password</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="koba-input"
                    required
                    autoComplete="new-password"
                    minLength={6}
                  />
                </div>

                <div>
                  <label className="koba-label">Confirm New Password</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="koba-input"
                    required
                    autoComplete="new-password"
                    minLength={6}
                  />
                </div>

                <button
                  type="submit"
                  className="koba-btn koba-btn-primary"
                >
                  Change Password
                </button>
              </form>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
