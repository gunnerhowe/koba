'use client';

import { useState, useEffect } from 'react';
import { useAuth, useRequireAuth } from '@/lib/auth';
import AppShell from '@/components/AppShell';
import ConfirmDialog from '@/components/ConfirmDialog';
import Spinner from '@/components/Spinner';
import { API_BASE } from '@/lib/api';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

interface APIKey {
  id: string;
  tenant_id: string;
  tenant_name?: string;
  name: string;
  key_prefix: string;
  permissions: string[];
  rate_limit: number | null;
  is_active: boolean;
  last_used_at: string | null;
  created_at: string;
  expires_at: string | null;
}

interface Tenant {
  id: string;
  name: string;
  slug: string;
}

export default function APIKeysPage() {
  const { user, loading: authLoading } = useRequireAuth();
  const { token } = useAuth();
  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newKeyResult, setNewKeyResult] = useState<{ key: string; id: string } | null>(null);
  const [confirmAction, setConfirmAction] = useState<{open: boolean, title: string, message: string, variant?: 'danger' | 'warning' | 'default', onConfirm: () => void}>({open: false, title: '', message: '', onConfirm: () => {}});

  // Form state
  const [formData, setFormData] = useState({
    tenant_id: '',
    name: '',
    permissions: [] as string[],
    rate_limit: '',
    expires_days: '',
  });

  const availablePermissions = [
    'tools:execute',
    'tools:read',
    'receipts:read',
    'receipts:write',
    'policy:read',
    'audit:read',
    'approvals:read',
    'approvals:grant',
    'approvals:deny',
  ];

  useEffect(() => {
    if (token) {
      fetchTenants();
    }
  }, [token]);

  // Escape key handler for modal
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (showCreateModal) {
          setShowCreateModal(false);
          setFormData({ tenant_id: '', name: '', permissions: [], rate_limit: '', expires_days: '' });
        }
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [showCreateModal]);

  const fetchTenants = async () => {
    try {
      const response = await fetch(`${API_BASE}/v1/admin/tenants`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setTenants(data.tenants || []);
      }
    } catch (err) {
      // Ignore tenant fetch errors
    }
  };

  const fetchAPIKeys = async () => {
    try {
      setLoading(true);
      // Fetch keys for all tenants
      const allKeys: APIKey[] = [];

      for (const tenant of tenants) {
        try {
          const response = await fetch(`${API_BASE}/v1/tenant/api-keys?tenant_id=${tenant.id}`, {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          });

          if (response.ok) {
            const data = await response.json();
            const keysWithTenant = (data.api_keys || []).map((key: APIKey) => ({
              ...key,
              tenant_name: tenant.name,
            }));
            allKeys.push(...keysWithTenant);
          }
        } catch (err) {
          // Ignore individual tenant errors
        }
      }

      setApiKeys(allKeys);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  // Refetch keys when tenants change
  useEffect(() => {
    if (tenants.length > 0 && token) {
      fetchAPIKeys();
    }
  }, [tenants, token]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      interface CreateAPIKeyPayload {
        name: string;
        permissions: string[];
        rate_limit?: number;
        expires_at?: string;
      }

      const payload: CreateAPIKeyPayload = {
        name: formData.name,
        permissions: formData.permissions,
      };

      if (formData.rate_limit) {
        payload.rate_limit = parseInt(formData.rate_limit, 10);
      }

      if (formData.expires_days) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + parseInt(formData.expires_days, 10));
        payload.expires_at = expiresAt.toISOString();
      }

      const response = await fetch(`${API_BASE}/v1/tenant/api-keys?tenant_id=${formData.tenant_id}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to create API key');
      }

      const result = await response.json();
      setNewKeyResult({ key: result.api_key, id: result.id });
      setShowCreateModal(false);
      setFormData({ tenant_id: '', name: '', permissions: [], rate_limit: '', expires_days: '' });
      fetchAPIKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  const handleRevoke = (key: APIKey) => {
    setConfirmAction({
      open: true,
      title: 'Revoke API Key',
      message: `Are you sure you want to revoke API key "${key.name}"? This action cannot be undone.`,
      variant: 'danger',
      onConfirm: async () => {
        setConfirmAction(prev => ({...prev, open: false}));
        try {
          const response = await fetch(`${API_BASE}/v1/tenant/api-keys/${key.id}?tenant_id=${key.tenant_id}`, {
            method: 'DELETE',
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          });

          if (!response.ok) {
            throw new Error('Failed to revoke API key');
          }

          fetchAPIKeys();
        } catch (err) {
          setError(err instanceof Error ? err.message : 'An error occurred');
        }
      },
    });
  };

  const togglePermission = (permission: string) => {
    setFormData(prev => ({
      ...prev,
      permissions: prev.permissions.includes(permission)
        ? prev.permissions.filter(p => p !== permission)
        : [...prev.permissions, permission],
    }));
  };

  if (authLoading || loading) {
    return (
      <AppShell>
        <Spinner size="md" className="h-64" />
      </AppShell>
    );
  }

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-koba-text">API Keys</h1>
              <HelpButton content={helpContent.apiKeys} />
            </div>
            <p className="text-koba-text-secondary mt-1">Manage API keys across all tenants</p>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 bg-koba-accent text-koba-text rounded-lg hover:bg-koba-accent/90 transition-colors flex items-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Create API Key
          </button>
        </div>

        {/* Error display */}
        {error && (
          <div className="bg-koba-danger-muted border border-koba-danger/20 rounded-lg p-4 text-koba-danger">
            {error}
            <button onClick={() => setError(null)} className="ml-2 underline">Dismiss</button>
          </div>
        )}

        {/* New key result */}
        {newKeyResult && (
          <div className="bg-koba-success-muted border border-koba-success/20 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <svg className="w-6 h-6 text-koba-success flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="flex-1">
                <h3 className="text-koba-success font-medium">API Key Created Successfully</h3>
                <p className="text-koba-success/70 text-sm mt-1 mb-3">
                  Copy this key now - it won't be shown again!
                </p>
                <div className="bg-koba-bg rounded-lg p-3">
                  <code className="text-koba-success text-sm break-all select-all">{newKeyResult.key}</code>
                </div>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(newKeyResult.key);
                  }}
                  className="mt-2 px-3 py-1.5 text-sm bg-koba-success text-koba-text rounded hover:bg-koba-success/90 transition-colors"
                >
                  Copy to Clipboard
                </button>
              </div>
              <button
                onClick={() => setNewKeyResult(null)}
                className="text-koba-success hover:text-koba-success"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-koba-bg-card rounded-lg p-4 border border-koba-border">
            <p className="text-koba-text-secondary text-sm">Total API Keys</p>
            <p className="text-2xl font-bold text-koba-text">{apiKeys.length}</p>
          </div>
          <div className="bg-koba-bg-card rounded-lg p-4 border border-koba-border">
            <p className="text-koba-text-secondary text-sm">Active</p>
            <p className="text-2xl font-bold text-koba-success">
              {apiKeys.filter(k => k.is_active).length}
            </p>
          </div>
          <div className="bg-koba-bg-card rounded-lg p-4 border border-koba-border">
            <p className="text-koba-text-secondary text-sm">Tenants with Keys</p>
            <p className="text-2xl font-bold text-koba-accent">
              {new Set(apiKeys.map(k => k.tenant_id)).size}
            </p>
          </div>
        </div>

        {/* API Keys table */}
        <div className="bg-koba-bg-card rounded-lg border border-koba-border overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full">
            <caption className="sr-only">API key management table</caption>
            <thead className="bg-koba-bg">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Key</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Tenant</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Permissions</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Last Used</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-koba-border">
              {apiKeys.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-koba-text-secondary">
                    No API keys found. Create one to get started.
                  </td>
                </tr>
              ) : (
                apiKeys.map((key) => (
                  <tr key={key.id} className="hover:bg-koba-bg-elevated/50">
                    <td className="px-6 py-4">
                      <div>
                        <p className="text-koba-text font-medium">{key.name}</p>
                        <code className="text-koba-text-secondary text-sm">{key.key_prefix}...</code>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="text-koba-text">{key.tenant_name || key.tenant_id.slice(0, 8)}</span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {key.permissions.slice(0, 3).map(perm => (
                          <span key={perm} className="px-1.5 py-0.5 text-xs bg-koba-bg-elevated text-koba-text rounded">
                            {perm.split(':')[1]}
                          </span>
                        ))}
                        {key.permissions.length > 3 && (
                          <span className="px-1.5 py-0.5 text-xs bg-koba-bg-elevated text-koba-text-secondary rounded">
                            +{key.permissions.length - 3} more
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${key.is_active ? 'bg-koba-success-muted text-koba-success border-koba-success/20' : 'bg-koba-danger-muted text-koba-danger border-koba-danger/20'}`}>
                        {key.is_active ? 'Active' : 'Revoked'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-koba-text-secondary text-sm">
                      {key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      {key.is_active && (
                        <button
                          onClick={() => handleRevoke(key)}
                          className="px-3 py-1.5 text-sm text-koba-danger hover:text-koba-danger hover:bg-koba-danger-muted rounded-lg transition-colors"
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          </div>
        </div>
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-koba-bg-card rounded-lg p-6 w-full max-w-lg border border-koba-border max-h-[90vh] overflow-y-auto" role="dialog" aria-modal="true">
            <h2 className="text-xl font-bold text-koba-text mb-4">Create API Key</h2>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-1">Tenant</label>
                <select
                  value={formData.tenant_id}
                  onChange={(e) => setFormData({ ...formData, tenant_id: e.target.value })}
                  className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent"
                  required
                >
                  <option value="">Select a tenant...</option>
                  {tenants.map(tenant => (
                    <option key={tenant.id} value={tenant.id}>{tenant.name}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-1">Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent"
                  placeholder="Production API Key"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-2">Permissions</label>
                <div className="grid grid-cols-2 gap-2">
                  {availablePermissions.map(perm => (
                    <label key={perm} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={formData.permissions.includes(perm)}
                        onChange={() => togglePermission(perm)}
                        className="w-4 h-4 rounded bg-koba-bg border-koba-border text-koba-accent focus:ring-koba-accent"
                      />
                      <span className="text-koba-text text-sm">{perm}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-koba-text-secondary mb-1">Rate Limit (req/min)</label>
                  <input
                    type="number"
                    value={formData.rate_limit}
                    onChange={(e) => setFormData({ ...formData, rate_limit: e.target.value })}
                    className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent"
                    placeholder="1000"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-koba-text-secondary mb-1">Expires In (days)</label>
                  <input
                    type="number"
                    value={formData.expires_days}
                    onChange={(e) => setFormData({ ...formData, expires_days: e.target.value })}
                    className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent"
                    placeholder="365"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateModal(false);
                    setFormData({ tenant_id: '', name: '', permissions: [], rate_limit: '', expires_days: '' });
                  }}
                  className="px-4 py-2 text-koba-text-secondary hover:text-koba-text transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!formData.tenant_id || !formData.name || formData.permissions.length === 0}
                  className="px-4 py-2 bg-koba-accent text-koba-text rounded-lg hover:bg-koba-accent/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Create API Key
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <ConfirmDialog
        isOpen={confirmAction.open}
        title={confirmAction.title}
        message={confirmAction.message}
        confirmLabel="Confirm"
        variant={confirmAction.variant}
        onConfirm={confirmAction.onConfirm}
        onCancel={() => setConfirmAction(prev => ({...prev, open: false}))}
      />
    </AppShell>
  );
}
