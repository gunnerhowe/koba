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

interface User {
  id: string;
  email: string;
  username: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login: string | null;
  permissions: string[];
}

const ROLE_STYLES: Record<string, string> = {
  super_admin: 'bg-koba-accent-muted text-koba-accent',
  admin: 'bg-koba-accent-muted text-koba-accent-light',
  operator: 'bg-koba-success-muted text-koba-success',
  viewer: 'bg-koba-bg-elevated text-koba-text-muted',
};

export default function UsersPage() {
  const router = useRouter();
  const { user, token, loading: authLoading, hasPermission } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const { toasts, showToast, dismissToast } = useToast();

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  useEffect(() => {
    if (!user || !hasPermission('users:read')) return;

    async function loadUsers() {
      try {
        const res = await fetch(`${API_BASE}/v1/users`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setUsers(data.users || []);
        }
      } catch (e) {
        console.error('Failed to load users', e);
      } finally {
        setLoading(false);
      }
    }

    loadUsers();
  }, [user, token, hasPermission]);

  const deleteUser = async (userId: string) => {
    if (!confirm('Are you sure you want to delete this user?')) return;

    try {
      const res = await fetch(`${API_BASE}/v1/users/${userId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        setUsers(users.filter((u) => u.id !== userId));
        showToast('User deleted successfully', 'success');
      } else {
        showToast('Failed to delete user', 'error');
      }
    } catch (e) {
      console.error('Failed to delete user', e);
      showToast('Failed to delete user', 'error');
    }
  };

  const toggleUserStatus = async (userId: string, isActive: boolean) => {
    try {
      const res = await fetch(`${API_BASE}/v1/users/${userId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ is_active: !isActive }),
      });
      if (res.ok) {
        setUsers(users.map((u) =>
          u.id === userId ? { ...u, is_active: !isActive } : u
        ));
        showToast(`User ${!isActive ? 'enabled' : 'disabled'}`, 'success');
      } else {
        showToast('Failed to update user status', 'error');
      }
    } catch (e) {
      console.error('Failed to update user', e);
      showToast('Failed to update user status', 'error');
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

  if (!hasPermission('users:read')) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center py-16">
          <div className="w-16 h-16 bg-koba-danger-muted rounded-2xl flex items-center justify-center mb-4">
            <svg className="w-8 h-8 text-koba-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-koba-text mb-2">Access Restricted</h2>
          <p className="text-koba-text-secondary">You don't have permission to view users.</p>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-8">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl sm:text-3xl font-bold text-koba-text">User Management</h1>
              <HelpButton content={helpContent.users} />
            </div>
            <p className="text-koba-text-secondary mt-1">Manage user accounts and permissions</p>
          </div>
          {hasPermission('users:create') && (
            <button
              onClick={() => setShowCreateModal(true)}
              className="koba-btn koba-btn-primary gap-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add User
            </button>
          )}
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="w-12 h-12 border-4 border-koba-accent/30 border-t-koba-accent rounded-full animate-spin" />
          </div>
        ) : users.length === 0 ? (
          <div className="koba-card text-center py-12">
            <div className="w-16 h-16 bg-koba-bg-elevated rounded-2xl flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8 text-koba-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-koba-text mb-2">No Users Found</h3>
            <p className="text-koba-text-secondary text-sm">Create your first user to get started.</p>
          </div>
        ) : (
          <div className="koba-card overflow-hidden p-0">
            <table className="w-full">
              <caption className="sr-only">User accounts list</caption>
              <thead className="bg-koba-bg-elevated border-b border-koba-border">
                <tr>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">
                    User
                  </th>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">
                    Role
                  </th>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">
                    Status
                  </th>
                  <th scope="col" className="px-6 py-4 text-left text-xs font-medium text-koba-text-secondary uppercase tracking-wider">
                    Last Login
                  </th>
                  <th scope="col" className="px-6 py-4 text-right text-xs font-medium text-koba-text-secondary uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-koba-border">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-koba-bg-elevated/50 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-koba-accent-muted rounded-full flex items-center justify-center">
                          <span className="text-koba-accent font-medium">
                            {u.username.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <div className="ml-4">
                          <div className="text-koba-text font-medium">{u.username}</div>
                          <div className="text-koba-text-muted text-sm">{u.email}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`koba-badge ${ROLE_STYLES[u.role] || ROLE_STYLES.viewer}`}>
                        {u.role.replace('_', ' ').toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <button
                        onClick={() => toggleUserStatus(u.id, u.is_active)}
                        disabled={!hasPermission('users:update') || u.id === user?.id}
                        className={`koba-badge transition-colors ${
                          u.is_active
                            ? 'bg-koba-success-muted text-koba-success hover:bg-koba-success/20'
                            : 'bg-koba-danger-muted text-koba-danger hover:bg-koba-danger/20'
                        } ${(!hasPermission('users:update') || u.id === user?.id) ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
                      >
                        {u.is_active ? 'ACTIVE' : 'DISABLED'}
                      </button>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-koba-text-muted text-sm">
                      {u.last_login
                        ? new Date(u.last_login).toLocaleString()
                        : 'Never'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <div className="flex justify-end gap-2">
                        {hasPermission('users:update') && (
                          <button
                            onClick={() => setEditingUser(u)}
                            className="p-2 text-koba-text-muted hover:text-koba-text hover:bg-koba-bg-elevated rounded-lg transition-colors"
                            aria-label={`Edit ${u.username}`}
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                          </button>
                        )}
                        {hasPermission('users:delete') && u.id !== user?.id && (
                          <button
                            onClick={() => deleteUser(u.id)}
                            className="p-2 text-koba-text-muted hover:text-koba-danger hover:bg-koba-danger-muted rounded-lg transition-colors"
                            aria-label={`Delete ${u.username}`}
                          >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Create User Modal */}
        {showCreateModal && (
          <CreateUserModal
            token={token}
            onClose={() => setShowCreateModal(false)}
            onCreated={(newUser) => {
              setUsers([...users, newUser]);
              setShowCreateModal(false);
              showToast('User created successfully', 'success');
            }}
            onError={(msg) => showToast(msg, 'error')}
          />
        )}

        {/* Edit User Modal */}
        {editingUser && (
          <EditUserModal
            user={editingUser}
            token={token}
            onClose={() => setEditingUser(null)}
            onUpdated={(updatedUser) => {
              setUsers(users.map((u) => (u.id === updatedUser.id ? updatedUser : u)));
              setEditingUser(null);
              showToast('User updated successfully', 'success');
            }}
            onError={(msg) => showToast(msg, 'error')}
          />
        )}
      </div>
    </AppShell>
  );
}

function CreateUserModal({ token, onClose, onCreated, onError }: {
  token: string | null;
  onClose: () => void;
  onCreated: (user: User) => void;
  onError: (msg: string) => void;
}) {
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    role: 'viewer',
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/v1/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(formData),
      });

      if (res.ok) {
        const data = await res.json();
        onCreated(data.user);
      } else {
        const error = await res.json();
        onError(error.detail || 'Failed to create user');
      }
    } catch (e) {
      onError('Failed to create user');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-koba-bg-card border border-koba-border rounded-2xl max-w-md w-full shadow-xl animate-fade-in"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-6 border-b border-koba-border">
          <h2 className="text-xl font-semibold text-koba-text">Create User</h2>
          <button
            onClick={onClose}
            className="p-2 text-koba-text-muted hover:text-koba-text hover:bg-koba-bg-elevated rounded-lg transition-colors"
            aria-label="Close"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div>
            <label className="koba-label">Email</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              className="koba-input"
              placeholder="user@example.com"
              required
              autoComplete="email"
            />
          </div>

          <div>
            <label className="koba-label">Username</label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              className="koba-input"
              placeholder="johndoe"
              required
              autoComplete="username"
            />
          </div>

          <div>
            <label className="koba-label">Password</label>
            <input
              type="password"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              className="koba-input"
              placeholder="Minimum 6 characters"
              required
              autoComplete="new-password"
              minLength={6}
            />
          </div>

          <div>
            <label className="koba-label">Role</label>
            <select
              value={formData.role}
              onChange={(e) => setFormData({ ...formData, role: e.target.value })}
              className="koba-input"
            >
              <option value="viewer">Viewer</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
              <option value="super_admin">Super Admin</option>
            </select>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="koba-btn koba-btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="koba-btn koba-btn-primary"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Creating...
                </>
              ) : (
                'Create User'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function EditUserModal({ user: editUser, token, onClose, onUpdated, onError }: {
  user: User;
  token: string | null;
  onClose: () => void;
  onUpdated: (user: User) => void;
  onError: (msg: string) => void;
}) {
  const [formData, setFormData] = useState({
    email: editUser.email,
    username: editUser.username,
    role: editUser.role,
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await fetch(`${API_BASE}/v1/users/${editUser.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(formData),
      });

      if (res.ok) {
        const updatedUser = await res.json();
        onUpdated(updatedUser);
      } else {
        const error = await res.json();
        onError(error.detail || 'Failed to update user');
      }
    } catch (e) {
      onError('Failed to update user');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div
        className="bg-koba-bg-card border border-koba-border rounded-2xl max-w-md w-full shadow-xl animate-fade-in"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-6 border-b border-koba-border">
          <h2 className="text-xl font-semibold text-koba-text">Edit User</h2>
          <button
            onClick={onClose}
            className="p-2 text-koba-text-muted hover:text-koba-text hover:bg-koba-bg-elevated rounded-lg transition-colors"
            aria-label="Close"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div>
            <label className="koba-label">Email</label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              className="koba-input"
              required
              autoComplete="email"
            />
          </div>

          <div>
            <label className="koba-label">Username</label>
            <input
              type="text"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              className="koba-input"
              required
              autoComplete="username"
            />
          </div>

          <div>
            <label className="koba-label">Role</label>
            <select
              value={formData.role}
              onChange={(e) => setFormData({ ...formData, role: e.target.value })}
              className="koba-input"
            >
              <option value="viewer">Viewer</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
              <option value="super_admin">Super Admin</option>
            </select>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="koba-btn koba-btn-secondary"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="koba-btn koba-btn-primary"
            >
              {loading ? (
                <>
                  <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Saving...
                </>
              ) : (
                'Save Changes'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
