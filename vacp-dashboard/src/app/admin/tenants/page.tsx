'use client';

import { useState, useEffect } from 'react';
import { useAuth, useRequireAuth } from '@/lib/auth';
import AppShell from '@/components/AppShell';
import ConfirmDialog from '@/components/ConfirmDialog';
import Spinner from '@/components/Spinner';
import { API_BASE } from '@/lib/api';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

interface Tenant {
  id: string;
  name: string;
  slug: string;
  status: string;
  plan: string;
  created_at: string;
  updated_at: string;
  settings?: Record<string, any>;
  resource_limits?: Record<string, any>;
}

export default function TenantsPage() {
  const { user, loading: authLoading } = useRequireAuth();
  const { token } = useAuth();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [confirmAction, setConfirmAction] = useState<{open: boolean, title: string, message: string, variant?: 'danger' | 'warning' | 'default', onConfirm: () => void}>({open: false, title: '', message: '', onConfirm: () => {}});

  // Form state
  const [formData, setFormData] = useState({
    name: '',
    slug: '',
    plan: 'starter',
  });

  useEffect(() => {
    if (token) {
      fetchTenants();
    }
  }, [token]);

  // Escape key handler for modals
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (showCreateModal) {
          setShowCreateModal(false);
          setFormData({ name: '', slug: '', plan: 'starter' });
        }
        if (showEditModal) {
          setShowEditModal(false);
          setSelectedTenant(null);
          setFormData({ name: '', slug: '', plan: 'starter' });
        }
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [showCreateModal, showEditModal]);

  const fetchTenants = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE}/v1/admin/tenants`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch tenants');
      }

      const data = await response.json();
      setTenants(data.tenants || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_BASE}/v1/admin/tenants`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to create tenant');
      }

      setShowCreateModal(false);
      setFormData({ name: '', slug: '', plan: 'starter' });
      fetchTenants();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTenant) return;

    try {
      const response = await fetch(`${API_BASE}/v1/admin/tenants/${selectedTenant.id}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'Failed to update tenant');
      }

      setShowEditModal(false);
      setSelectedTenant(null);
      setFormData({ name: '', slug: '', plan: 'starter' });
      fetchTenants();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  const handleSuspend = (tenant: Tenant) => {
    setConfirmAction({
      open: true,
      title: 'Suspend Tenant',
      message: `Are you sure you want to suspend ${tenant.name}? Their agents will be blocked.`,
      variant: 'warning',
      onConfirm: async () => {
        setConfirmAction(prev => ({...prev, open: false}));
        try {
          const response = await fetch(`${API_BASE}/v1/admin/tenants/${tenant.id}/suspend`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          });

          if (!response.ok) {
            throw new Error('Failed to suspend tenant');
          }

          fetchTenants();
        } catch (err) {
          setError(err instanceof Error ? err.message : 'An error occurred');
        }
      },
    });
  };

  const handleActivate = async (tenant: Tenant) => {
    try {
      const response = await fetch(`${API_BASE}/v1/admin/tenants/${tenant.id}/activate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to activate tenant');
      }

      fetchTenants();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    }
  };

  const handleDelete = (tenant: Tenant) => {
    setConfirmAction({
      open: true,
      title: 'Delete Tenant',
      message: `Are you sure you want to delete ${tenant.name}? This action cannot be undone.`,
      variant: 'danger',
      onConfirm: async () => {
        setConfirmAction(prev => ({...prev, open: false}));
        try {
          const response = await fetch(`${API_BASE}/v1/admin/tenants/${tenant.id}`, {
            method: 'DELETE',
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          });

          if (!response.ok) {
            throw new Error('Failed to delete tenant');
          }

          fetchTenants();
        } catch (err) {
          setError(err instanceof Error ? err.message : 'An error occurred');
        }
      },
    });
  };

  const openEditModal = (tenant: Tenant) => {
    setSelectedTenant(tenant);
    setFormData({
      name: tenant.name,
      slug: tenant.slug,
      plan: tenant.plan,
    });
    setShowEditModal(true);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-koba-success-muted text-koba-success border-koba-success/20';
      case 'suspended':
        return 'bg-koba-danger-muted text-koba-danger border-koba-danger/20';
      case 'pending':
        return 'bg-koba-warning-muted text-koba-warning border-koba-warning/20';
      default:
        return 'bg-koba-bg-elevated text-koba-text-secondary border-koba-border';
    }
  };

  const getPlanColor = (plan: string) => {
    switch (plan) {
      case 'enterprise':
        return 'bg-koba-accent-muted text-koba-accent border-koba-accent/20';
      case 'business':
        return 'bg-koba-accent-muted text-koba-accent border-koba-accent/20';
      case 'starter':
        return 'bg-koba-info-muted text-koba-info border-koba-info/20';
      default:
        return 'bg-koba-bg-elevated text-koba-text-secondary border-koba-border';
    }
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
              <h1 className="text-2xl font-bold text-koba-text">Tenant Management</h1>
              <HelpButton content={helpContent.tenants} />
            </div>
            <p className="text-koba-text-secondary mt-1">Manage multi-tenant organizations</p>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 bg-koba-accent text-koba-text rounded-lg hover:bg-koba-accent/90 transition-colors flex items-center gap-2"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Create Tenant
          </button>
        </div>

        {/* Error display */}
        {error && (
          <div className="bg-koba-danger-muted border border-koba-danger/20 rounded-lg p-4 text-koba-danger">
            {error}
            <button onClick={() => setError(null)} className="ml-2 underline">Dismiss</button>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-koba-bg-card rounded-lg p-4 border border-koba-border">
            <p className="text-koba-text-secondary text-sm">Total Tenants</p>
            <p className="text-2xl font-bold text-koba-text">{tenants.length}</p>
          </div>
          <div className="bg-koba-bg-card rounded-lg p-4 border border-koba-border">
            <p className="text-koba-text-secondary text-sm">Active</p>
            <p className="text-2xl font-bold text-koba-success">
              {tenants.filter(t => t.status === 'active').length}
            </p>
          </div>
          <div className="bg-koba-bg-card rounded-lg p-4 border border-koba-border">
            <p className="text-koba-text-secondary text-sm">Suspended</p>
            <p className="text-2xl font-bold text-koba-danger">
              {tenants.filter(t => t.status === 'suspended').length}
            </p>
          </div>
          <div className="bg-koba-bg-card rounded-lg p-4 border border-koba-border">
            <p className="text-koba-text-secondary text-sm">Enterprise</p>
            <p className="text-2xl font-bold text-koba-accent">
              {tenants.filter(t => t.plan === 'enterprise').length}
            </p>
          </div>
        </div>

        {/* Tenants table */}
        <div className="bg-koba-bg-card rounded-lg border border-koba-border overflow-hidden">
          <div className="overflow-x-auto">
          <table className="w-full">
            <caption className="sr-only">Tenant management table</caption>
            <thead className="bg-koba-bg">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Tenant</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Slug</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Plan</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Created</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-koba-text-secondary uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-koba-border">
              {tenants.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-koba-text-secondary">
                    No tenants found. Create one to get started.
                  </td>
                </tr>
              ) : (
                tenants.map((tenant) => (
                  <tr key={tenant.id} className="hover:bg-koba-bg-elevated/50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-8 h-8 bg-gradient-to-br from-koba-accent to-koba-accent-hover rounded-lg flex items-center justify-center mr-3">
                          <span className="text-koba-text font-medium text-sm">
                            {tenant.name.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <p className="text-koba-text font-medium">{tenant.name}</p>
                          <p className="text-koba-text-secondary text-sm font-mono">{tenant.id.slice(0, 8)}...</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <code className="text-koba-text bg-koba-bg px-2 py-1 rounded">{tenant.slug}</code>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getStatusColor(tenant.status)}`}>
                        {tenant.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getPlanColor(tenant.plan)}`}>
                        {tenant.plan}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-koba-text-secondary text-sm">
                      {new Date(tenant.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => openEditModal(tenant)}
                          className="p-2 text-koba-text-secondary hover:text-koba-text hover:bg-koba-bg-elevated rounded-lg transition-colors"
                          title="Edit"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        {tenant.status === 'active' ? (
                          <button
                            onClick={() => handleSuspend(tenant)}
                            className="p-2 text-koba-warning hover:text-koba-warning hover:bg-koba-warning-muted rounded-lg transition-colors"
                            title="Suspend"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                          </button>
                        ) : (
                          <button
                            onClick={() => handleActivate(tenant)}
                            className="p-2 text-koba-success hover:text-koba-success hover:bg-koba-success-muted rounded-lg transition-colors"
                            title="Activate"
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                          </button>
                        )}
                        <button
                          onClick={() => handleDelete(tenant)}
                          className="p-2 text-koba-danger hover:text-koba-danger hover:bg-koba-danger-muted rounded-lg transition-colors"
                          title="Delete"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
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
          <div className="bg-koba-bg-card rounded-lg p-6 w-full max-w-md border border-koba-border" role="dialog" aria-modal="true">
            <h2 className="text-xl font-bold text-koba-text mb-4">Create Tenant</h2>
            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-1">Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent"
                  placeholder="Acme Corporation"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-1">Slug</label>
                <input
                  type="text"
                  value={formData.slug}
                  onChange={(e) => setFormData({ ...formData, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '-') })}
                  className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent font-mono"
                  placeholder="acme-corp"
                  required
                />
                <p className="text-xs text-koba-text-muted mt-1">URL-friendly identifier (lowercase, hyphens only)</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-1">Plan</label>
                <select
                  value={formData.plan}
                  onChange={(e) => setFormData({ ...formData, plan: e.target.value })}
                  className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent"
                >
                  <option value="free">Free</option>
                  <option value="starter">Starter</option>
                  <option value="business">Business</option>
                  <option value="enterprise">Enterprise</option>
                </select>
              </div>
              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateModal(false);
                    setFormData({ name: '', slug: '', plan: 'starter' });
                  }}
                  className="px-4 py-2 text-koba-text-secondary hover:text-koba-text transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-koba-accent text-koba-text rounded-lg hover:bg-koba-accent/90 transition-colors"
                >
                  Create Tenant
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Modal */}
      {showEditModal && selectedTenant && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-koba-bg-card rounded-lg p-6 w-full max-w-md border border-koba-border" role="dialog" aria-modal="true">
            <h2 className="text-xl font-bold text-koba-text mb-4">Edit Tenant</h2>
            <form onSubmit={handleUpdate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-1">Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-1">Slug</label>
                <input
                  type="text"
                  value={formData.slug}
                  onChange={(e) => setFormData({ ...formData, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '-') })}
                  className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-koba-text-secondary mb-1">Plan</label>
                <select
                  value={formData.plan}
                  onChange={(e) => setFormData({ ...formData, plan: e.target.value })}
                  className="w-full px-3 py-2 bg-koba-bg border border-koba-border rounded-lg text-koba-text focus:outline-none focus:ring-2 focus:ring-koba-accent/50 focus:border-koba-accent"
                >
                  <option value="free">Free</option>
                  <option value="starter">Starter</option>
                  <option value="business">Business</option>
                  <option value="enterprise">Enterprise</option>
                </select>
              </div>
              <div className="flex justify-end gap-3 pt-4">
                <button
                  type="button"
                  onClick={() => {
                    setShowEditModal(false);
                    setSelectedTenant(null);
                    setFormData({ name: '', slug: '', plan: 'starter' });
                  }}
                  className="px-4 py-2 text-koba-text-secondary hover:text-koba-text transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-koba-accent text-koba-text rounded-lg hover:bg-koba-accent/90 transition-colors"
                >
                  Save Changes
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
