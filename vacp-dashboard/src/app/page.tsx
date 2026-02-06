'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import AppShell from '@/components/AppShell';
import StatCard from '@/components/StatCard';
import { useAuth } from '@/lib/auth';
import { API_BASE } from '@/lib/api';
import { Activity, CheckCircle, XCircle, Clock, Zap } from 'lucide-react';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

interface Stats {
  gateway?: {
    total_requests: number;
    allowed: number;
    denied: number;
    pending_approval: number;
    errors: number;
  };
  audit_log?: {
    size: number;
    root: string;
  };
}

interface Analytics {
  decisions: Record<string, number>;
  top_categories: { name: string; count: number }[];
  pending_approvals: number;
}

interface Receipt {
  receipt_id: string;
  timestamp: string;
  agent_id: string;
  session_id: string;
  tool: {
    id: string;
    name: string;
  };
  policy: {
    decision: string;
  };
}

export default function Dashboard() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();
  const [stats, setStats] = useState<Stats | null>(null);
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [wsConnected, setWsConnected] = useState(false);

  // Redirect to landing page if not authenticated
  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  useEffect(() => {
    if (!user) return;

    async function loadData() {
      try {
        const headers: HeadersInit = {};
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }

        const [statsRes, receiptsRes, analyticsRes] = await Promise.all([
          fetch(`${API_BASE}/stats`, { headers }),
          fetch(`${API_BASE}/v1/audit/entries?limit=10`, { headers }),
          fetch(`${API_BASE}/v1/analytics`, { headers }),
        ]);

        if (statsRes.ok) {
          setStats(await statsRes.json());
        }
        if (receiptsRes.ok) {
          const data = await receiptsRes.json();
          setReceipts(data.entries || []);
        }
        if (analyticsRes.ok) {
          setAnalytics(await analyticsRes.json());
        }
        setError(null);
      } catch (err) {
        setError('Failed to connect to Koba server');
      } finally {
        setLoading(false);
      }
    }

    loadData();
    const interval = setInterval(loadData, 30000);

    // Connect WebSocket for real-time updates
    let ws: WebSocket | null = null;
    try {
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const apiHost = new URL(API_BASE).host;
      const wsUrl = `${wsProtocol}//${apiHost}/ws/audit${token ? `?token=${token}` : ''}`;
      ws = new WebSocket(wsUrl);
      ws.onopen = () => setWsConnected(true);
      ws.onclose = () => setWsConnected(false);
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'receipt') {
            loadData();
          }
        } catch {
          console.warn('Invalid WebSocket message received');
        }
      };
    } catch (e) {
      console.log('WebSocket not available');
    }

    return () => {
      clearInterval(interval);
      ws?.close();
    };
  }, [user, token]);

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

  const gateway = stats?.gateway || { total_requests: 0, allowed: 0, denied: 0, pending_approval: 0, errors: 0 };

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold text-koba-text">Dashboard</h1>
            <HelpButton content={helpContent.dashboard} />
          </div>
          <p className="text-koba-text-secondary mt-1">
            Real-time monitoring of AI agent actions
          </p>
        </div>

        {error ? (
          <div className="koba-card border-koba-danger/30 bg-koba-danger-muted/50">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 bg-koba-danger-muted rounded-xl flex items-center justify-center flex-shrink-0">
                <svg className="w-6 h-6 text-koba-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <p className="text-koba-danger font-semibold">Connection Error</p>
                <p className="text-koba-text-secondary text-sm mt-1">{error}</p>
                <p className="text-koba-text-muted text-sm mt-3">
                  Start the server: <code className="px-2 py-1 bg-koba-bg-elevated rounded text-koba-accent font-mono text-xs">python -m vacp.api.server</code>
                </p>
              </div>
            </div>
          </div>
        ) : loading ? (
          <div className="flex flex-col items-center justify-center py-20">
            <div className="w-12 h-12 border-4 border-koba-accent/30 border-t-koba-accent rounded-full animate-spin mb-4" />
            <p className="text-koba-text-secondary">Loading dashboard data...</p>
          </div>
        ) : (
          <>
            {/* Stats Grid */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 mb-8">
              <StatCard
                title="Actions"
                value={gateway.total_requests}
                icon={Activity}
                color="accent"
              />
              <StatCard
                title="Allowed"
                value={gateway.allowed}
                icon={CheckCircle}
                color="success"
              />
              <StatCard
                title="Blocked"
                value={gateway.denied}
                icon={XCircle}
                color="danger"
              />
              <StatCard
                title="Pending"
                value={gateway.pending_approval}
                icon={Clock}
                color="warning"
              />
            </div>

            {/* Analytics Charts */}
            {analytics && gateway.total_requests > 0 && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                {/* Decision Breakdown */}
                <div className="koba-card">
                  <h3 className="text-lg font-semibold text-koba-text mb-4">Decision Breakdown</h3>
                  <div className="space-y-3">
                    {[
                      { key: 'allow', label: 'Allowed', color: 'bg-koba-success', count: analytics.decisions.allow || 0 },
                      { key: 'deny', label: 'Blocked', color: 'bg-koba-danger', count: analytics.decisions.deny || 0 },
                      { key: 'pending_approval', label: 'Pending Approval', color: 'bg-koba-warning', count: analytics.decisions.pending_approval || 0 },
                    ].map(item => {
                      const total = Object.values(analytics.decisions).reduce((a, b) => a + b, 0) || 1;
                      const pct = Math.round((item.count / total) * 100);
                      return (
                        <div key={item.key}>
                          <div className="flex justify-between text-sm mb-1">
                            <span className="text-koba-text-secondary">{item.label}</span>
                            <span className="text-koba-text font-medium">{item.count} ({pct}%)</span>
                          </div>
                          <div className="h-3 bg-koba-bg-elevated rounded-full overflow-hidden">
                            <div className={`h-full ${item.color} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Top Categories */}
                <div className="koba-card">
                  <h3 className="text-lg font-semibold text-koba-text mb-4">Top Tool Categories</h3>
                  {analytics.top_categories.length === 0 ? (
                    <p className="text-koba-text-muted text-sm">No category data yet</p>
                  ) : (
                    <div className="space-y-3">
                      {analytics.top_categories.slice(0, 6).map((cat, idx) => {
                        const maxCount = analytics.top_categories[0]?.count || 1;
                        const pct = Math.round((cat.count / maxCount) * 100);
                        return (
                          <div key={cat.name}>
                            <div className="flex justify-between text-sm mb-1">
                              <span className="text-koba-text-secondary capitalize">{cat.name}</span>
                              <span className="text-koba-text font-medium">{cat.count}</span>
                            </div>
                            <div className="h-3 bg-koba-bg-elevated rounded-full overflow-hidden">
                              <div className="h-full bg-koba-accent rounded-full transition-all duration-500" style={{ width: `${pct}%`, opacity: 1 - (idx * 0.12) }} />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Getting Started */}
            {stats && stats.gateway && stats.gateway.total_requests === 0 && (
              <div className="koba-card p-6 mb-6 border-koba-accent/30 bg-koba-accent/5">
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 rounded-xl bg-koba-accent/20 flex items-center justify-center flex-shrink-0">
                    <Zap className="w-6 h-6 text-koba-accent" />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-koba-text mb-1">Get Started with Koba</h3>
                    <p className="text-koba-text-secondary text-sm mb-4">
                      Connect your AI agent to start monitoring and governing its actions.
                    </p>
                    <div className="flex gap-3">
                      <a href="/integrations" className="koba-btn koba-btn-primary text-sm">
                        Connect Your AI
                      </a>
                      <a href="/tools" className="koba-btn bg-koba-bg-secondary hover:bg-koba-bg-elevated text-koba-text text-sm">
                        Set Up Tools
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Merkle Tree Status */}
            {stats?.audit_log && (
              <div className="koba-card mb-8">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-koba-accent to-purple-600 flex items-center justify-center shadow-glow-sm">
                      <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
                      </svg>
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-koba-text">Activity Log</h2>
                      <p className="text-koba-text-muted text-sm">Secure record of all AI actions</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-koba-success animate-pulse' : 'bg-koba-text-muted'}`} />
                    <span className="text-sm text-koba-text-secondary">{wsConnected ? 'Live' : 'Polling'}</span>
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 pt-4 border-t border-koba-border">
                  <div>
                    <p className="text-koba-text-muted text-xs uppercase tracking-wider mb-1">Log Size</p>
                    <p className="text-2xl font-bold text-koba-accent">{stats.audit_log.size}</p>
                  </div>
                  <div className="sm:col-span-2">
                    <p className="text-koba-text-muted text-xs uppercase tracking-wider mb-1">Log Integrity</p>
                    <p className="font-mono text-sm text-koba-text-secondary break-all">
                      {stats.audit_log.root || 'Empty log'}
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Recent Actions */}
            <div className="koba-card p-0 overflow-hidden">
              <div className="p-6 border-b border-koba-border">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-lg font-semibold text-koba-text">Recent Actions</h2>
                    <p className="text-koba-text-muted text-sm mt-1">Latest AI agent tool executions</p>
                  </div>
                  <span className="koba-badge koba-badge-accent">{receipts.length} shown</span>
                </div>
              </div>
              <div className="divide-y divide-koba-border">
                {receipts.length === 0 ? (
                  <div className="p-12 text-center">
                    <div className="w-16 h-16 bg-koba-bg-elevated rounded-2xl flex items-center justify-center mx-auto mb-4">
                      <svg className="w-8 h-8 text-koba-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                    </div>
                    <h3 className="text-koba-text font-medium mb-2">No actions recorded yet</h3>
                    <p className="text-koba-text-secondary text-sm">
                      Use the Demo page to generate sample AI actions
                    </p>
                  </div>
                ) : (
                  receipts.map((receipt) => (
                    <ReceiptRow key={receipt.receipt_id} receipt={receipt} />
                  ))
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </AppShell>
  );
}

function ReceiptRow({ receipt }: { receipt: Receipt }) {
  const decisionStyles = {
    allow: { badge: 'koba-badge-success', label: 'Allowed' },
    deny: { badge: 'koba-badge-danger', label: 'Blocked' },
    pending_approval: { badge: 'koba-badge-warning', label: 'Pending' },
  } as const;

  const decision = receipt.policy?.decision || 'allow';
  const style = decisionStyles[decision as keyof typeof decisionStyles] || decisionStyles.allow;

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div className="p-4 hover:bg-koba-bg-elevated/50 transition-colors">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4 min-w-0 flex-1">
          <div className="w-10 h-10 bg-koba-bg-elevated rounded-xl flex items-center justify-center flex-shrink-0">
            <svg className="w-5 h-5 text-koba-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            </svg>
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-koba-text font-medium truncate">{receipt.tool?.name || receipt.tool?.id}</p>
            <p className="text-koba-text-muted text-sm truncate">
              {receipt.agent_id} • {formatTime(receipt.timestamp)}
            </p>
          </div>
        </div>
        <span className={`koba-badge ${style.badge} flex-shrink-0`}>
          {style.label}
        </span>
      </div>
      <div className="mt-2 pl-14">
        <p className="text-koba-text-muted text-xs font-mono truncate">
          {receipt.receipt_id}
        </p>
      </div>
    </div>
  );
}
