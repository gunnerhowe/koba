'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import AppShell from '@/components/AppShell';
import { useAuth } from '@/lib/auth';
import { API_BASE } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import ToastContainer from '@/components/Toast';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

interface RevealedModification {
  description?: string;
  modification_type?: string;
  target?: string;
  component?: string;
  module?: string;
  code?: string | Record<string, unknown>;
  changes?: string | Record<string, unknown>;
  proposed_changes?: string | Record<string, unknown>;
  reason?: string;
  justification?: string;
  impact?: string;
  risk_level?: 'low' | 'medium' | 'high';
}

interface CognitiveAlert {
  severity: 'info' | 'alert' | 'critical';
  tripwire_name: string;
  timestamp: string;
  details?: Record<string, unknown>;
}

interface ModificationCommitment {
  commitment_id: string;
  modification_type: string;
  commitment_hash: string;
  committed_at: string;
  min_delay_seconds: number;
  executable_after: string;
  status: string;
  required_approvers: number;
  approvals: string[];
  rejections: string[];
  revealed_modification: RevealedModification | null;
}

interface TripwireStatus {
  name: string;
  severity: string;
  triggered_count: number;
  last_triggered: string | null;
}

interface ContainmentStatus {
  operational: boolean;
  kill_switch: {
    activated: boolean;
    required_keys: number;
    registered_key_holders: number;
    signatures_received: number;
  };
  resource_usage: {
    tokens_this_hour: number;
    tokens_limit: number;
    requests_last_minute: number;
    requests_limit: number;
  };
  cognitive_tripwires: Record<string, TripwireStatus>;
  pending_modifications: number;
  recent_alerts: number;
}

export default function ContainmentPage() {
  const router = useRouter();
  const { user, token, loading: authLoading, hasPermission } = useAuth();
  const [status, setStatus] = useState<ContainmentStatus | null>(null);
  const [modifications, setModifications] = useState<ModificationCommitment[]>([]);
  const [alerts, setAlerts] = useState<CognitiveAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTab, setSelectedTab] = useState<'overview' | 'modifications' | 'killswitch' | 'cognitive'>('overview');
  const { toasts, showToast, dismissToast } = useToast();
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    if (!token) return;
    try {
      const [statusRes, modsRes, cogRes] = await Promise.all([
        fetch(`${API_BASE}/v1/containment/status`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        fetch(`${API_BASE}/v1/containment/modifications`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        fetch(`${API_BASE}/v1/containment/cognitive/status`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      ]);

      if (statusRes.ok) {
        setStatus(await statusRes.json());
      }
      if (modsRes.ok) {
        const data = await modsRes.json();
        setModifications(data.modifications || []);
      }
      if (cogRes.ok) {
        const data = await cogRes.json();
        setAlerts(data.recent_alerts || []);
      }
    } catch (e) {
      console.error('Failed to load containment data', e);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  useEffect(() => {
    if (!user || !hasPermission('system:admin')) return;

    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [user, hasPermission, loadData]);

  const approveModification = async (commitmentId: string) => {
    setActionLoading(commitmentId);
    try {
      const res = await fetch(`${API_BASE}/v1/containment/modifications/${commitmentId}/approve`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        showToast('Modification approved successfully', 'success');
        await loadData();
      } else {
        const data = await res.json().catch(() => ({}));
        showToast(data.detail || 'Failed to approve modification', 'error');
      }
    } catch (e) {
      showToast('Failed to approve modification', 'error');
    } finally {
      setActionLoading(null);
    }
  };

  const rejectModification = async (commitmentId: string) => {
    setActionLoading(commitmentId);
    try {
      const res = await fetch(`${API_BASE}/v1/containment/modifications/${commitmentId}/reject`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ reason: 'Rejected by admin' }),
      });
      if (res.ok) {
        showToast('Modification rejected', 'success');
        await loadData();
      } else {
        const data = await res.json().catch(() => ({}));
        showToast(data.detail || 'Failed to reject modification', 'error');
      }
    } catch (e) {
      showToast('Failed to reject modification', 'error');
    } finally {
      setActionLoading(null);
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

  if (!hasPermission('system:admin')) {
    return (
      <AppShell>
        <div className="max-w-md mx-auto text-center py-16">
          <div className="w-16 h-16 mx-auto mb-6 bg-koba-warning-muted rounded-2xl flex items-center justify-center">
            <svg className="w-8 h-8 text-koba-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-koba-text mb-2">Admin Access Required</h2>
          <p className="text-koba-text-secondary mb-6">
            Safeguarding controls require system administrator privileges. These features are protected to ensure only authorized team members can manage AI oversight settings.
          </p>
          <p className="text-koba-text-muted text-sm">
            Contact your system administrator for access.
          </p>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="max-w-7xl mx-auto">
        <div className="mb-6 sm:mb-8">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold text-koba-text">AI Safeguarding System</h1>
            <HelpButton content={helpContent.safeguarding} />
          </div>
          <p className="text-koba-text-secondary mt-1 text-sm sm:text-base">
            Cryptographic oversight for AI self-modification — your boundaries, enforced
          </p>
          <div className="mt-3 sm:mt-4 p-3 sm:p-4 bg-koba-accent-muted border border-koba-accent/20 rounded-xl">
            <p className="text-koba-text text-xs sm:text-sm">
              <strong>What appears here:</strong> Requests from AI to modify its own code, weights, or behavior.
              Different from <a href="/approvals" className="text-koba-accent hover:text-koba-accent-light underline">Tool Approvals</a> (emails, files, payments).
            </p>
          </div>
        </div>

        {/* System Status Banner */}
        {status && (
          <div className={`mb-4 sm:mb-6 p-3 sm:p-4 rounded-xl border ${
            status.operational && !status.kill_switch.activated
              ? 'bg-koba-success-muted border-koba-success/30'
              : 'bg-koba-danger-muted border-koba-danger/30'
          }`}>
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 sm:gap-0">
              <div className="flex items-center gap-2 sm:gap-3">
                <div className={`w-3 h-3 sm:w-4 sm:h-4 rounded-full animate-pulse flex-shrink-0 ${
                  status.operational && !status.kill_switch.activated
                    ? 'bg-koba-success'
                    : 'bg-koba-danger'
                }`} />
                <span className={`font-semibold text-sm sm:text-base ${
                  status.operational && !status.kill_switch.activated
                    ? 'text-koba-success'
                    : 'text-koba-danger'
                }`}>
                  {status.kill_switch.activated ? 'KILL SWITCH ACTIVATED' :
                   status.operational ? 'SAFEGUARDING ACTIVE' : 'SYSTEM OFFLINE'}
                </span>
              </div>
              <div className="flex items-center gap-4 sm:gap-6 text-xs sm:text-sm">
                <span className="text-koba-text-secondary">
                  Pending: <span className="text-koba-text font-medium">{status.pending_modifications}</span>
                </span>
                <span className="text-koba-text-secondary">
                  Alerts: <span className="text-koba-warning font-medium">{status.recent_alerts}</span>
                </span>
              </div>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 mb-4 sm:mb-6 p-1 bg-koba-bg-elevated rounded-xl overflow-x-auto -mx-4 px-4 sm:mx-0 sm:px-0" role="tablist">
          {(['overview', 'modifications', 'killswitch', 'cognitive'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setSelectedTab(tab)}
              role="tab"
              aria-selected={selectedTab === tab}
              className={`px-3 sm:px-4 py-2 rounded-lg text-xs sm:text-sm font-medium transition-all whitespace-nowrap flex-shrink-0 ${
                selectedTab === tab
                  ? 'bg-koba-accent text-white shadow-glow-sm'
                  : 'text-koba-text-secondary hover:text-koba-text hover:bg-koba-bg-card'
              }`}
            >
              {tab === 'overview' && 'Overview'}
              {tab === 'modifications' && 'Modifications'}
              {tab === 'killswitch' && 'Kill Switch'}
              {tab === 'cognitive' && 'Cognitive'}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center h-64 gap-4">
            <div className="w-12 h-12 border-4 border-koba-accent/30 border-t-koba-accent rounded-full animate-spin" />
            <p className="text-koba-text-secondary text-sm">Loading safeguarding data...</p>
          </div>
        ) : (
          <>
            {/* Overview Tab */}
            {selectedTab === 'overview' && status && (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
                {/* Self-Modification Controls */}
                <div className="koba-card">
                  <div className="flex items-center gap-2 sm:gap-3 mb-3 sm:mb-4">
                    <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-koba-accent-muted flex items-center justify-center flex-shrink-0">
                      <svg className="w-5 h-5 text-koba-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-koba-text font-semibold text-sm sm:text-base">Self-Modification</h3>
                      <p className="text-koba-text-secondary text-xs sm:text-sm">Commit-reveal scheme active</p>
                    </div>
                  </div>
                  <div className="space-y-2 text-xs sm:text-sm">
                    <div className="flex justify-between">
                      <span className="text-koba-text-secondary">Pending</span>
                      <span className="text-koba-text">{status.pending_modifications}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-koba-text-secondary">Min delay (code)</span>
                      <span className="text-koba-text">24 hours</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-koba-text-secondary">Required approvers</span>
                      <span className="text-koba-text">2</span>
                    </div>
                  </div>
                </div>

                {/* Kill Switch */}
                <div className="koba-card">
                  <div className="flex items-center gap-2 sm:gap-3 mb-3 sm:mb-4">
                    <div className={`w-8 h-8 sm:w-10 sm:h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
                      status.kill_switch.activated ? 'bg-koba-danger-muted' : 'bg-koba-danger/10'
                    }`}>
                      <svg className="w-4 h-4 sm:w-5 sm:h-5 text-koba-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                      </svg>
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-koba-text font-semibold text-sm sm:text-base">Kill Switch</h3>
                      <p className={`text-xs sm:text-sm ${status.kill_switch.activated ? 'text-koba-danger' : 'text-koba-success'}`}>
                        {status.kill_switch.activated ? 'ACTIVATED' : 'Armed & Ready'}
                      </p>
                    </div>
                  </div>
                  <div className="space-y-2 text-xs sm:text-sm">
                    <div className="flex justify-between">
                      <span className="text-koba-text-secondary">Required keys</span>
                      <span className="text-koba-text">{status.kill_switch.required_keys}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-koba-text-secondary">Registered holders</span>
                      <span className="text-koba-text">{status.kill_switch.registered_key_holders}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-koba-text-secondary">Signatures received</span>
                      <span className="text-koba-text">{status.kill_switch.signatures_received}</span>
                    </div>
                  </div>
                </div>

                {/* Resource Usage */}
                <div className="koba-card">
                  <div className="flex items-center gap-2 sm:gap-3 mb-3 sm:mb-4">
                    <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-koba-info-muted flex items-center justify-center flex-shrink-0">
                      <svg className="w-4 h-4 sm:w-5 sm:h-5 text-koba-info" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                      </svg>
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-koba-text font-semibold text-sm sm:text-base">Resource Limits</h3>
                      <p className="text-koba-text-secondary text-xs sm:text-sm">Your boundaries, protected</p>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <div className="flex justify-between text-xs sm:text-sm mb-1">
                        <span className="text-koba-text-secondary">Tokens/hr</span>
                        <span className="text-koba-text">
                          {status.resource_usage.tokens_this_hour.toLocaleString()} / {status.resource_usage.tokens_limit.toLocaleString()}
                        </span>
                      </div>
                      <div className="w-full bg-koba-bg-elevated rounded-full h-1.5 sm:h-2">
                        <div
                          className="bg-koba-info h-1.5 sm:h-2 rounded-full"
                          style={{ width: `${Math.min(100, (status.resource_usage.tokens_this_hour / status.resource_usage.tokens_limit) * 100)}%` }}
                        />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-xs sm:text-sm mb-1">
                        <span className="text-koba-text-secondary">Req/min</span>
                        <span className="text-koba-text">
                          {status.resource_usage.requests_last_minute} / {status.resource_usage.requests_limit}
                        </span>
                      </div>
                      <div className="w-full bg-koba-bg-elevated rounded-full h-1.5 sm:h-2">
                        <div
                          className="bg-koba-success h-1.5 sm:h-2 rounded-full"
                          style={{ width: `${Math.min(100, (status.resource_usage.requests_last_minute / status.resource_usage.requests_limit) * 100)}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Cognitive Tripwires */}
                <div className="koba-card sm:col-span-2 lg:col-span-3">
                  <div className="flex items-center gap-2 sm:gap-3 mb-3 sm:mb-4">
                    <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-koba-warning-muted flex items-center justify-center flex-shrink-0">
                      <svg className="w-4 h-4 sm:w-5 sm:h-5 text-koba-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-koba-text font-semibold text-sm sm:text-base">Behavior Monitors</h3>
                      <p className="text-koba-text-secondary text-xs sm:text-sm">Watching for unexpected patterns</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2 sm:gap-4">
                    {Object.entries(status.cognitive_tripwires).map(([id, tw]) => (
                      <div key={id} className={`p-2 sm:p-3 rounded-lg ${
                        tw.triggered_count > 0 ? 'bg-koba-danger-muted border border-koba-danger/30' : 'bg-koba-bg-elevated'
                      }`}>
                        <p className="text-xs sm:text-sm font-medium text-koba-text truncate">{tw.name}</p>
                        <p className={`text-xs ${
                          tw.severity === 'critical' ? 'text-koba-danger' :
                          tw.severity === 'alert' ? 'text-koba-warning' : 'text-koba-text-muted'
                        }`}>
                          {tw.severity.toUpperCase()}
                        </p>
                        <p className="text-base sm:text-lg font-bold text-koba-text mt-1">{tw.triggered_count}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Modifications Tab */}
            {selectedTab === 'modifications' && (
              <div className="koba-card overflow-hidden">
                <div className="p-4 sm:p-6 border-b border-koba-border">
                  <h2 className="text-base sm:text-lg font-semibold text-koba-text">Pending Self-Modifications</h2>
                  <p className="text-koba-text-secondary text-xs sm:text-sm mt-1">
                    All AI self-modifications require commitment + delay + approval
                  </p>
                </div>
                {modifications.length === 0 ? (
                  <div className="p-8 sm:p-12 text-center">
                    <div className="w-16 h-16 bg-koba-success-muted rounded-2xl flex items-center justify-center mx-auto mb-4">
                      <svg className="w-8 h-8 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <h3 className="text-lg font-medium text-koba-text mb-2">No pending modifications</h3>
                    <p className="text-koba-text-secondary text-sm">The AI has not requested any self-modifications</p>
                  </div>
                ) : (
                  <div className="divide-y divide-koba-border">
                    {modifications.map((mod) => (
                      <div key={mod.commitment_id} className="p-4 sm:p-6">
                        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2 sm:gap-3">
                              <span className={`koba-badge ${
                                mod.status === 'approved' ? 'koba-badge-success' :
                                mod.status === 'rejected' ? 'koba-badge-danger' :
                                'koba-badge-warning'
                              }`}>
                                {mod.status.toUpperCase().replace('_', ' ')}
                              </span>
                              <span className="text-koba-text font-medium text-sm sm:text-base">{mod.modification_type}</span>
                            </div>
                            <p className="text-koba-text-muted text-xs sm:text-sm mt-2 font-mono truncate">{mod.commitment_hash}</p>
                            <div className="flex flex-col sm:flex-row sm:gap-6 gap-1 mt-2 text-xs sm:text-sm">
                              <span className="text-koba-text-secondary">
                                Min delay: <span className="text-koba-text">{mod.min_delay_seconds}s</span>
                              </span>
                              <span className="text-koba-text-secondary truncate">
                                After: <span className="text-koba-text">{new Date(mod.executable_after).toLocaleString()}</span>
                              </span>
                              <span className="text-koba-text-secondary">
                                Approvals: <span className="text-koba-text">{mod.approvals.length}/{mod.required_approvers}</span>
                              </span>
                            </div>
                          </div>
                          {mod.status === 'pending_approval' && (
                            <div className="flex gap-2 w-full sm:w-auto flex-shrink-0">
                              <button
                                onClick={() => approveModification(mod.commitment_id)}
                                disabled={actionLoading === mod.commitment_id}
                                className="koba-btn koba-btn-success flex-1 sm:flex-none text-xs sm:text-sm"
                              >
                                {actionLoading === mod.commitment_id && (
                                  <svg className="animate-spin h-4 w-4 mr-1" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                  </svg>
                                )}
                                Approve
                              </button>
                              <button
                                onClick={() => rejectModification(mod.commitment_id)}
                                disabled={actionLoading === mod.commitment_id}
                                className="koba-btn koba-btn-danger flex-1 sm:flex-none text-xs sm:text-sm"
                              >
                                {actionLoading === mod.commitment_id && (
                                  <svg className="animate-spin h-4 w-4 mr-1" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                  </svg>
                                )}
                                Reject
                              </button>
                            </div>
                          )}
                        </div>
                        {mod.revealed_modification && (
                          <div className="mt-4 space-y-4">
                            <div className="p-4 bg-koba-bg-elevated rounded-xl border border-koba-border">
                              <p className="text-koba-text-muted text-xs uppercase tracking-wider mb-3">Modification Details</p>

                              {/* Description */}
                              {mod.revealed_modification.description && (
                                <div className="mb-4">
                                  <p className="text-sm text-koba-text-secondary mb-1">Description</p>
                                  <p className="text-koba-text">{mod.revealed_modification.description}</p>
                                </div>
                              )}

                              {/* Modification Type Info */}
                              {mod.revealed_modification.modification_type && (
                                <div className="mb-4">
                                  <p className="text-sm text-koba-text-secondary mb-1">Type</p>
                                  <span className="inline-block px-3 py-1 bg-koba-accent-muted text-koba-accent rounded-full text-sm">
                                    {mod.revealed_modification.modification_type}
                                  </span>
                                </div>
                              )}

                              {/* Target Component/Module */}
                              {(mod.revealed_modification.target || mod.revealed_modification.component || mod.revealed_modification.module) && (
                                <div className="mb-4">
                                  <p className="text-sm text-koba-text-secondary mb-1">Target</p>
                                  <code className="bg-koba-bg-card px-2 py-1 rounded text-koba-info border border-koba-border">
                                    {mod.revealed_modification.target || mod.revealed_modification.component || mod.revealed_modification.module}
                                  </code>
                                </div>
                              )}

                              {/* Proposed Changes / Code */}
                              {(mod.revealed_modification.code || mod.revealed_modification.changes || mod.revealed_modification.proposed_changes) && (() => {
                                const codeValue = mod.revealed_modification.code || mod.revealed_modification.changes || mod.revealed_modification.proposed_changes;
                                const displayValue = typeof codeValue === 'string' ? codeValue : JSON.stringify(codeValue, null, 2);
                                return (
                                  <div className="mb-4">
                                    <p className="text-sm text-koba-text-secondary mb-2">Proposed Code Changes</p>
                                    <div className="bg-koba-bg border border-koba-border rounded-xl overflow-hidden">
                                      <div className="flex items-center gap-2 px-3 py-2 bg-koba-bg-card border-b border-koba-border">
                                        <div className="w-3 h-3 rounded-full bg-koba-danger/60"></div>
                                        <div className="w-3 h-3 rounded-full bg-koba-warning/60"></div>
                                        <div className="w-3 h-3 rounded-full bg-koba-success/60"></div>
                                        <span className="text-koba-text-muted text-xs ml-2">code changes</span>
                                      </div>
                                      <pre className="p-4 text-sm text-koba-text-secondary overflow-x-auto whitespace-pre-wrap font-mono">
                                        {displayValue}
                                      </pre>
                                    </div>
                                  </div>
                                );
                              })()}

                              {/* Reason / Justification */}
                              {(mod.revealed_modification.reason || mod.revealed_modification.justification) && (
                                <div className="mb-4">
                                  <p className="text-sm text-koba-text-secondary mb-1">Reason</p>
                                  <p className="text-koba-text-secondary italic">"{mod.revealed_modification.reason || mod.revealed_modification.justification}"</p>
                                </div>
                              )}

                              {/* Impact Assessment */}
                              {mod.revealed_modification.impact && (
                                <div className="mb-4">
                                  <p className="text-sm text-koba-text-secondary mb-1">Impact Assessment</p>
                                  <p className="text-koba-warning">{mod.revealed_modification.impact}</p>
                                </div>
                              )}

                              {/* Risk Level */}
                              {mod.revealed_modification.risk_level && (
                                <div className="mb-4">
                                  <p className="text-sm text-koba-text-secondary mb-1">Risk Level</p>
                                  <span className={`inline-block px-3 py-1 rounded-full text-sm ${
                                    mod.revealed_modification.risk_level === 'high' ? 'bg-koba-danger-muted text-koba-danger' :
                                    mod.revealed_modification.risk_level === 'medium' ? 'bg-koba-warning-muted text-koba-warning' :
                                    'bg-koba-success-muted text-koba-success'
                                  }`}>
                                    {mod.revealed_modification.risk_level.toUpperCase()}
                                  </span>
                                </div>
                              )}

                              {/* Raw JSON Fallback - collapsed by default */}
                              <details className="mt-4">
                                <summary className="text-koba-text-muted text-xs cursor-pointer hover:text-koba-text-secondary">
                                  View raw JSON data
                                </summary>
                                <pre className="mt-2 p-3 bg-koba-bg rounded-lg text-xs text-koba-text-muted overflow-x-auto font-mono">
                                  {JSON.stringify(mod.revealed_modification, null, 2)}
                                </pre>
                              </details>
                            </div>

                            {/* Warning banner */}
                            <div className="p-4 bg-koba-warning-muted border border-koba-warning/30 rounded-xl flex items-start gap-3">
                              <svg className="w-5 h-5 text-koba-warning flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                              </svg>
                              <div>
                                <p className="text-koba-warning font-medium text-sm">Review Carefully</p>
                                <p className="text-koba-text-secondary text-sm mt-1">
                                  This modification will alter the AI system's behavior. Ensure you understand the changes before approving.
                                </p>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Kill Switch Tab */}
            {selectedTab === 'killswitch' && status && (
              <div className="space-y-6">
                <div className={`p-8 rounded-2xl border-2 ${
                  status.kill_switch.activated
                    ? 'bg-koba-danger-muted border-koba-danger'
                    : 'bg-koba-bg-card border-koba-border'
                }`}>
                  <div className="text-center">
                    <div className={`w-20 h-20 mx-auto rounded-full flex items-center justify-center ${
                      status.kill_switch.activated ? 'bg-koba-danger' : 'bg-koba-bg-elevated'
                    }`}>
                      <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                      </svg>
                    </div>
                    <h2 className={`text-2xl font-bold mt-4 ${
                      status.kill_switch.activated ? 'text-koba-danger' : 'text-koba-text'
                    }`}>
                      {status.kill_switch.activated ? 'SYSTEM HALTED' : 'Kill Switch Armed'}
                    </h2>
                    <p className="text-koba-text-secondary mt-2">
                      {status.kill_switch.activated
                        ? 'All AI operations have been immediately terminated'
                        : `Requires ${status.kill_switch.required_keys} key holder signatures to activate`}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-6">
                  <div className="koba-card text-center">
                    <p className="text-4xl font-bold text-koba-text">{status.kill_switch.required_keys}</p>
                    <p className="text-koba-text-secondary mt-1">Required Keys</p>
                  </div>
                  <div className="koba-card text-center">
                    <p className="text-4xl font-bold text-koba-text">{status.kill_switch.registered_key_holders}</p>
                    <p className="text-koba-text-secondary mt-1">Key Holders</p>
                  </div>
                  <div className="koba-card text-center">
                    <p className="text-4xl font-bold text-koba-warning">{status.kill_switch.signatures_received}</p>
                    <p className="text-koba-text-secondary mt-1">Signatures Received</p>
                  </div>
                </div>

                <div className="koba-card">
                  <h3 className="text-lg font-semibold text-koba-text mb-4">How the Kill Switch Works</h3>
                  <div className="space-y-4 text-koba-text-secondary">
                    <div className="flex gap-4">
                      <div className="w-8 h-8 rounded-full bg-koba-accent-muted flex items-center justify-center flex-shrink-0">
                        <span className="text-koba-accent font-bold">1</span>
                      </div>
                      <p>Each key holder has a unique Ed25519 private key stored offline</p>
                    </div>
                    <div className="flex gap-4">
                      <div className="w-8 h-8 rounded-full bg-koba-accent-muted flex items-center justify-center flex-shrink-0">
                        <span className="text-koba-accent font-bold">2</span>
                      </div>
                      <p>To activate, key holders sign the message "ACTIVATE_KILL_SWITCH:[timestamp]"</p>
                    </div>
                    <div className="flex gap-4">
                      <div className="w-8 h-8 rounded-full bg-koba-accent-muted flex items-center justify-center flex-shrink-0">
                        <span className="text-koba-accent font-bold">3</span>
                      </div>
                      <p>Once {status.kill_switch.required_keys} valid signatures are received, the system immediately halts</p>
                    </div>
                    <div className="flex gap-4">
                      <div className="w-8 h-8 rounded-full bg-koba-danger-muted flex items-center justify-center flex-shrink-0">
                        <span className="text-koba-danger font-bold">!</span>
                      </div>
                      <p className="text-koba-danger">Cryptographically secured — you always maintain full control over this safeguard</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Cognitive Monitor Tab */}
            {selectedTab === 'cognitive' && (
              <div className="space-y-6">
                <div className="koba-card">
                  <h2 className="text-lg font-semibold text-koba-text mb-4">Recent Cognitive Alerts</h2>
                  {alerts.length === 0 ? (
                    <div className="text-center py-8">
                      <div className="w-16 h-16 bg-koba-success-muted rounded-2xl flex items-center justify-center mx-auto mb-4">
                        <svg className="w-8 h-8 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                      <h3 className="text-lg font-medium text-koba-text mb-2">No cognitive alerts</h3>
                      <p className="text-koba-text-secondary text-sm">All clear — no unexpected patterns detected in AI behavior</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {alerts.map((alert, i) => (
                        <div key={i} className={`p-4 rounded-xl border ${
                          alert.severity === 'critical' ? 'bg-koba-danger-muted border-koba-danger/30' :
                          alert.severity === 'alert' ? 'bg-koba-warning-muted border-koba-warning/30' :
                          'bg-koba-bg-elevated border-koba-border'
                        }`}>
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <span className={`koba-badge ${
                                alert.severity === 'critical' ? 'koba-badge-danger' :
                                alert.severity === 'alert' ? 'koba-badge-warning' :
                                'bg-koba-bg-card text-koba-text-secondary'
                              }`}>
                                {alert.severity.toUpperCase()}
                              </span>
                              <span className="text-koba-text font-medium">{alert.tripwire_name}</span>
                            </div>
                            <span className="text-koba-text-muted text-sm">{new Date(alert.timestamp).toLocaleString()}</span>
                          </div>
                          {alert.details && (
                            <pre className="mt-3 p-3 bg-koba-bg rounded-lg text-xs text-koba-text-secondary overflow-x-auto font-mono">
                              {JSON.stringify(alert.details, null, 2)}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="koba-card">
                  <h3 className="text-lg font-semibold text-koba-text mb-4">What We Monitor</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 bg-koba-bg-elevated rounded-xl">
                      <h4 className="text-koba-text font-medium">Intent Verification</h4>
                      <p className="text-koba-text-secondary text-sm mt-1">
                        Compares stated intent vs actual actions so you always know what happened
                      </p>
                    </div>
                    <div className="p-4 bg-koba-bg-elevated rounded-xl">
                      <h4 className="text-koba-text font-medium">Goal Drift</h4>
                      <p className="text-koba-text-secondary text-sm mt-1">
                        Tracks changes in stated objectives so you can spot unexpected shifts
                      </p>
                    </div>
                    <div className="p-4 bg-koba-bg-elevated rounded-xl">
                      <h4 className="text-koba-text font-medium">Influence Detection</h4>
                      <p className="text-koba-text-secondary text-sm mt-1">
                        Identifies unexpected attempts to influence humans or connected systems
                      </p>
                    </div>
                    <div className="p-4 bg-koba-bg-elevated rounded-xl">
                      <h4 className="text-koba-text font-medium">Access Monitoring</h4>
                      <p className="text-koba-text-secondary text-sm mt-1">
                        Alerts you when an agent attempts to access capabilities beyond its scope
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </AppShell>
  );
}
