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

interface Approval {
  approval_id: string;
  tool_id: string;
  agent_id: string;
  session_id: string;
  created_at: string;
  policy_decision: string;
  policy_rule_id?: string;
  request: {
    tool_id: string;
    parameters: Record<string, any>;
    agent_id: string;
    tenant_id: string;
  };
}

export default function ApprovalsPage() {
  const router = useRouter();
  const { user, token, loading: authLoading, hasPermission } = useAuth();
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState<string | null>(null);
  const { toasts, showToast, dismissToast } = useToast();
  const [rejectModal, setRejectModal] = useState<{ approvalId: string; toolId: string } | null>(null);
  const [approveModal, setApproveModal] = useState<{ approvalId: string; toolId: string } | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [expandedApproval, setExpandedApproval] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  useEffect(() => {
    if (!user || !hasPermission('approvals:read')) return;

    async function loadApprovals() {
      try {
        const res = await fetch(`${API_BASE}/v1/approvals`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setApprovals(data.approvals || []);
        }
      } catch (e) {
        console.error('Failed to load approvals', e);
      } finally {
        setLoading(false);
      }
    }

    loadApprovals();
    const interval = setInterval(loadApprovals, 5000);
    return () => clearInterval(interval);
  }, [user, token, hasPermission]);

  const processApproval = async (approvalId: string, approved: boolean, reason?: string) => {
    setProcessing(approvalId);
    try {
      const res = await fetch(`${API_BASE}/v1/approvals/${approvalId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ approved, reason }),
      });

      if (res.ok) {
        setApprovals(approvals.filter((a) => a.approval_id !== approvalId));
        showToast(approved ? 'Request approved' : 'Request rejected', 'success');
        setRejectModal(null);
        setRejectReason('');
      } else {
        const data = await res.json().catch(() => ({}));
        showToast(data.detail || 'Failed to process request', 'error');
      }
    } catch (e) {
      showToast('Failed to process request', 'error');
    } finally {
      setProcessing(null);
    }
  };

  // Close reject modal on escape
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && rejectModal) {
        setRejectModal(null);
        setRejectReason('');
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [rejectModal]);

  // Format relative time
  const formatRelativeTime = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return date.toLocaleDateString();
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

  if (!hasPermission('approvals:read')) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center py-16">
          <div className="w-16 h-16 bg-koba-danger-muted rounded-2xl flex items-center justify-center mb-4">
            <svg className="w-8 h-8 text-koba-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-koba-text mb-2">Access Restricted</h2>
          <p className="text-koba-text-secondary">You don't have permission to view approvals.</p>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Reject Modal */}
      {rejectModal && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => { setRejectModal(null); setRejectReason(''); }}
        >
          <div
            className="bg-koba-bg-card border border-koba-border rounded-2xl max-w-md w-full shadow-xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 border-b border-koba-border">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-koba-danger-muted rounded-xl flex items-center justify-center flex-shrink-0">
                  <svg className="w-6 h-6 text-koba-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-koba-text">Reject Request</h2>
                  <p className="text-koba-text-secondary text-sm mt-1">
                    Rejecting: <code className="px-1.5 py-0.5 bg-koba-bg-elevated rounded text-koba-accent">{rejectModal.toolId}</code>
                  </p>
                </div>
              </div>
            </div>
            <div className="p-6">
              <label className="koba-label">Reason (optional)</label>
              <textarea
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                placeholder="Explain why this request is being rejected..."
                rows={3}
                className="koba-input resize-none"
                autoFocus
              />
              <p className="koba-label-hint mt-2">This will be logged in the audit trail</p>
            </div>
            <div className="p-6 border-t border-koba-border flex justify-end gap-3">
              <button
                onClick={() => { setRejectModal(null); setRejectReason(''); }}
                className="koba-btn koba-btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={() => processApproval(rejectModal.approvalId, false, rejectReason || undefined)}
                disabled={processing === rejectModal.approvalId}
                className="koba-btn koba-btn-danger"
              >
                {processing === rejectModal.approvalId ? (
                  <>
                    <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Rejecting...
                  </>
                ) : (
                  'Reject Request'
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Approve Confirmation Modal */}
      {approveModal && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4"
          onClick={() => setApproveModal(null)}
        >
          <div
            className="bg-koba-bg-card border border-koba-border rounded-2xl max-w-md w-full shadow-xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6 border-b border-koba-border">
              <div className="flex items-start gap-4">
                <div className="w-12 h-12 bg-koba-success-muted rounded-xl flex items-center justify-center flex-shrink-0">
                  <svg className="w-6 h-6 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-koba-text">Approve Request?</h2>
                  <p className="text-koba-text-secondary text-sm mt-1">
                    Allow: <code className="px-1.5 py-0.5 bg-koba-bg-elevated rounded text-koba-accent">{approveModal.toolId}</code>
                  </p>
                </div>
              </div>
            </div>
            <div className="p-6">
              <p className="text-koba-text-secondary text-sm">
                This will allow the AI agent to execute this action. Make sure you have reviewed the request details before approving.
              </p>
            </div>
            <div className="p-6 border-t border-koba-border flex justify-end gap-3">
              <button
                onClick={() => setApproveModal(null)}
                className="koba-btn koba-btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  processApproval(approveModal.approvalId, true);
                  setApproveModal(null);
                }}
                disabled={processing === approveModal.approvalId}
                className="koba-btn koba-btn-success"
              >
                {processing === approveModal.approvalId ? (
                  <>
                    <svg className="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    Approving...
                  </>
                ) : (
                  'Yes, Approve'
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold text-koba-text">Pending Approvals</h1>
            <HelpButton content={helpContent.approvals} />
          </div>
          <p className="text-koba-text-secondary mt-1">
            Review AI agent requests that need human authorization
          </p>
        </div>

        {/* Info banner */}
        <div className="mb-6 p-4 bg-koba-info-muted border border-koba-info/20 rounded-xl">
          <div className="flex gap-3">
            <svg className="w-5 h-5 text-koba-info flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <p className="text-koba-text text-sm font-medium">What are approvals?</p>
              <p className="text-koba-text-secondary text-sm mt-1">
                When an AI agent tries to perform a sensitive action (like sending emails, accessing databases, or making payments),
                your security policy may require human approval first. Requests appear here and wait for your decision.
              </p>
            </div>
          </div>
        </div>

        {/* Approval count badge */}
        {!loading && approvals.length > 0 && (
          <div className="mb-4 flex items-center gap-2">
            <span className="px-3 py-1 bg-koba-warning-muted text-koba-warning rounded-full text-sm font-medium">
              {approvals.length} pending
            </span>
            <span className="text-koba-text-muted text-sm">Auto-refreshes every 5 seconds</span>
          </div>
        )}

        {loading ? (
          <div className="flex flex-col items-center justify-center py-16">
            <div className="w-12 h-12 border-4 border-koba-accent/30 border-t-koba-accent rounded-full animate-spin mb-4" />
            <p className="text-koba-text-secondary">Loading pending requests...</p>
          </div>
        ) : approvals.length === 0 ? (
          <div className="koba-card text-center py-16">
            <div className="w-20 h-20 bg-koba-success-muted rounded-2xl flex items-center justify-center mx-auto mb-6">
              <svg className="w-10 h-10 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h3 className="text-xl font-semibold text-koba-text mb-2">All Clear!</h3>
            <p className="text-koba-text-secondary max-w-sm mx-auto">
              No pending approval requests. When AI agents need authorization for sensitive actions, they'll appear here.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {approvals.map((approval) => {
              const isExpanded = expandedApproval === approval.approval_id;
              return (
                <div
                  key={approval.approval_id}
                  className="koba-card koba-card-interactive overflow-hidden"
                >
                  {/* Main content */}
                  <div className="flex flex-col sm:flex-row sm:items-center gap-4">
                    {/* Icon and info */}
                    <div className="flex items-start gap-4 flex-1 min-w-0">
                      <div className="w-12 h-12 bg-koba-warning-muted rounded-xl flex items-center justify-center flex-shrink-0">
                        <svg className="w-6 h-6 text-koba-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <h3 className="text-lg font-semibold text-koba-text">
                            {approval.tool_id}
                          </h3>
                          <span className="koba-badge koba-badge-warning">Awaiting Approval</span>
                        </div>
                        <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-sm text-koba-text-secondary">
                          <span className="flex items-center gap-1.5">
                            <svg className="w-4 h-4 text-koba-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                            </svg>
                            {approval.agent_id}
                          </span>
                          <span className="flex items-center gap-1.5">
                            <svg className="w-4 h-4 text-koba-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            {formatRelativeTime(approval.created_at)}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Action buttons */}
                    {hasPermission('approvals:grant') && (
                      <div className="flex gap-2 sm:flex-shrink-0">
                        <button
                          onClick={() => setApproveModal({ approvalId: approval.approval_id, toolId: approval.tool_id })}
                          disabled={processing === approval.approval_id}
                          className="koba-btn koba-btn-success flex-1 sm:flex-none"
                        >
                          {processing === approval.approval_id ? (
                            <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                            </svg>
                          ) : (
                            <>
                              <svg className="w-5 h-5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                              </svg>
                              Approve
                            </>
                          )}
                        </button>
                        <button
                          onClick={() => setRejectModal({ approvalId: approval.approval_id, toolId: approval.tool_id })}
                          disabled={processing === approval.approval_id}
                          className="koba-btn koba-btn-danger flex-1 sm:flex-none"
                        >
                          <svg className="w-5 h-5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                          </svg>
                          Reject
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Expandable details */}
                  <div className="mt-4 pt-4 border-t border-koba-border">
                    <button
                      onClick={() => setExpandedApproval(isExpanded ? null : approval.approval_id)}
                      className="flex items-center gap-2 text-sm text-koba-text-secondary hover:text-koba-text transition-colors"
                    >
                      <svg
                        className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                      {isExpanded ? 'Hide details' : 'View request details'}
                    </button>

                    {isExpanded && (
                      <div className="mt-4 space-y-4 animate-fade-in">
                        {/* Request parameters */}
                        <div>
                          <p className="text-xs font-medium text-koba-text-muted uppercase tracking-wider mb-2">
                            Request Parameters
                          </p>
                          <div className="p-4 bg-koba-bg-elevated rounded-xl overflow-x-auto">
                            <pre className="text-sm text-koba-text-secondary font-mono whitespace-pre-wrap break-all">
                              {JSON.stringify(approval.request?.parameters || {}, null, 2)}
                            </pre>
                          </div>
                        </div>

                        {/* Metadata */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          <div>
                            <p className="text-xs font-medium text-koba-text-muted uppercase tracking-wider mb-1">Session ID</p>
                            <code className="text-sm text-koba-text-secondary font-mono break-all">
                              {approval.session_id}
                            </code>
                          </div>
                          {approval.policy_rule_id && (
                            <div>
                              <p className="text-xs font-medium text-koba-text-muted uppercase tracking-wider mb-1">Matched Rule</p>
                              <code className="text-sm text-koba-text-secondary font-mono">
                                {approval.policy_rule_id}
                              </code>
                            </div>
                          )}
                          <div>
                            <p className="text-xs font-medium text-koba-text-muted uppercase tracking-wider mb-1">Requested At</p>
                            <span className="text-sm text-koba-text-secondary">
                              {new Date(approval.created_at).toLocaleString()}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppShell>
  );
}
