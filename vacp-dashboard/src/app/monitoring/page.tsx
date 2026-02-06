'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import AppShell from '@/components/AppShell';
import { useAuth } from '@/lib/auth';
import { API_BASE } from '@/lib/api';
import { useToast } from '@/hooks/useToast';
import ToastContainer from '@/components/Toast';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

// Static lookup tables - defined outside component to avoid recreation on each render
const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-koba-danger-muted text-koba-danger border-koba-danger/30',
  high: 'bg-koba-warning-muted text-koba-warning border-koba-warning/30',
  medium: 'bg-koba-warning-muted/60 text-koba-warning border-koba-warning/20',
  low: 'bg-koba-accent-muted text-koba-accent border-koba-accent/30',
};

interface AnomalyEvent {
  event_id: string;
  anomaly_type: string;
  session_id: string;
  agent_id: string;
  timestamp: string;
  score: number;
  confidence: number;
  description: string;
  triggered_action: string;
}

interface TripwireStats {
  total_events: number;
  active_sessions: number;
  high_risk_sessions: number;
  events_by_type: Record<string, number>;
}

interface CognitiveAlert {
  timestamp: string;
  type: string;
  stated_intent?: string;
  actual_action?: string;
  severity: string;
  details?: Record<string, any>;
}

export default function MonitoringPage() {
  const router = useRouter();
  const { user, token, loading: authLoading, hasPermission } = useAuth();
  const [events, setEvents] = useState<AnomalyEvent[]>([]);
  const [cognitiveAlerts, setCognitiveAlerts] = useState<CognitiveAlert[]>([]);
  const [tripwireStatus, setTripwireStatus] = useState<Record<string, any>>({});
  const [stats, setStats] = useState<TripwireStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTab, setSelectedTab] = useState<'events' | 'cognitive' | 'sessions'>('events');
  const { toasts, showToast, dismissToast } = useToast();

  const loadData = useCallback(async () => {
    if (!token) return;
    try {
      const [eventsRes, cognitiveRes, statsRes] = await Promise.all([
        fetch(`${API_BASE}/v1/tripwire/events?limit=50`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        fetch(`${API_BASE}/v1/containment/cognitive/status`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
        fetch(`${API_BASE}/stats`, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      ]);

      if (eventsRes.ok) {
        const data = await eventsRes.json();
        setEvents(data.events || []);
      }
      if (cognitiveRes.ok) {
        const data = await cognitiveRes.json();
        setTripwireStatus(data.tripwires || {});
        setCognitiveAlerts(data.recent_alerts || []);
      }
      if (statsRes.ok) {
        const data = await statsRes.json();
        setStats(data.tripwire || null);
      }
    } catch (e) {
      console.error('Failed to load monitoring data', e);
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
    if (!user || !hasPermission('audit:read')) return;
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [user, hasPermission, loadData]);

  const resetSession = async (sessionId: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/tripwire/session/${sessionId}/reset`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        showToast('Session state reset', 'success');
        loadData();
      } else {
        showToast('Failed to reset session', 'error');
      }
    } catch (e) {
      showToast('Failed to reset session', 'error');
    }
  };

  // Memoize expensive session aggregation computation
  const sessionData = useMemo(() => {
    const uniqueSessionIds = Array.from(new Set(events.map(e => e.session_id)));
    return uniqueSessionIds.map(sessionId => {
      const sessionEvents = events.filter(e => e.session_id === sessionId);
      const maxScore = sessionEvents.length > 0
        ? Math.max(...sessionEvents.map(e => e.score))
        : 0;
      return { sessionId, events: sessionEvents, maxScore };
    });
  }, [events]);

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

  if (!hasPermission('audit:read')) {
    return (
      <AppShell>
        <div className="flex flex-col items-center justify-center py-16">
          <div className="w-16 h-16 bg-koba-danger-muted rounded-2xl flex items-center justify-center mb-4">
            <svg className="w-8 h-8 text-koba-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-koba-text mb-2">Access Restricted</h2>
          <p className="text-koba-text-secondary">You don't have permission to view monitoring data.</p>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="max-w-7xl mx-auto">
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold text-koba-text">Activity Alerts</h1>
            <HelpButton content={helpContent.monitoring} />
          </div>
          <p className="text-koba-text-secondary mt-1">
            Monitors your AI agents and alerts you if something seems off
          </p>
        </div>

        {/* Stats Overview */}
        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="koba-card">
              <p className="text-koba-text-secondary text-sm">Total Events</p>
              <p className="text-3xl font-bold text-koba-text mt-1">{stats.total_events || 0}</p>
            </div>
            <div className="koba-card">
              <p className="text-koba-text-secondary text-sm">Active Sessions</p>
              <p className="text-3xl font-bold text-koba-accent mt-1">{stats.active_sessions || 0}</p>
            </div>
            <div className="koba-card">
              <p className="text-koba-text-secondary text-sm">High Risk Sessions</p>
              <p className="text-3xl font-bold text-koba-danger mt-1">{stats.high_risk_sessions || 0}</p>
            </div>
            <div className="koba-card">
              <p className="text-koba-text-secondary text-sm">Behavior Checks</p>
              <p className="text-3xl font-bold text-koba-warning mt-1">{cognitiveAlerts.length}</p>
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-2 mb-6" role="tablist">
          {(['events', 'cognitive', 'sessions'] as const).map((tab) => (
            <button
              key={tab}
              role="tab"
              aria-selected={selectedTab === tab}
              onClick={() => setSelectedTab(tab)}
              className={`px-4 py-2 rounded-xl font-medium transition-all ${
                selectedTab === tab
                  ? 'bg-koba-accent text-white shadow-glow-sm'
                  : 'bg-koba-bg-card text-koba-text-secondary hover:text-koba-text border border-koba-border'
              }`}
            >
              {tab === 'events' && 'Alert Events'}
              {tab === 'cognitive' && 'Safety Monitors'}
              {tab === 'sessions' && 'Session States'}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="w-12 h-12 border-4 border-koba-accent/30 border-t-koba-accent rounded-full animate-spin" />
          </div>
        ) : (
          <>
            {/* Anomaly Events Tab */}
            {selectedTab === 'events' && (
              <div className="koba-card overflow-hidden p-0">
                <div className="p-6 border-b border-koba-border">
                  <h2 className="text-lg font-semibold text-koba-text">Anomaly Events</h2>
                  <p className="text-koba-text-secondary text-sm mt-1">
                    Detected patterns that deviate from normal behavior
                  </p>
                </div>
                {events.length === 0 ? (
                  <div className="p-12 text-center">
                    <div className="w-16 h-16 bg-koba-success-muted rounded-2xl flex items-center justify-center mx-auto mb-4">
                      <svg className="w-8 h-8 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <h3 className="text-xl font-medium text-koba-text mb-2">No Anomalies Detected</h3>
                    <p className="text-koba-text-secondary">All agent behavior appears normal.</p>
                  </div>
                ) : (
                  <div className="divide-y divide-koba-border">
                    {events.map((event) => (
                      <div key={event.event_id} className="p-4 hover:bg-koba-bg-elevated/50 transition-colors">
                        <div className="flex items-start justify-between">
                          <div className="flex items-start gap-4">
                            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                              event.score > 0.8 ? 'bg-koba-danger-muted' : event.score > 0.5 ? 'bg-koba-warning-muted' : 'bg-koba-accent-muted'
                            }`}>
                              <svg className={`w-5 h-5 ${
                                event.score > 0.8 ? 'text-koba-danger' : event.score > 0.5 ? 'text-koba-warning' : 'text-koba-accent'
                              }`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                              </svg>
                            </div>
                            <div>
                              <p className="text-koba-text font-medium">{event.anomaly_type}</p>
                              <p className="text-koba-text-secondary text-sm">{event.description}</p>
                              <p className="text-koba-text-muted text-xs mt-1">
                                Agent: {event.agent_id} • Session: {event.session_id}
                              </p>
                            </div>
                          </div>
                          <div className="text-right">
                            <span className={`koba-badge ${
                              event.score > 0.8 ? 'bg-koba-danger-muted text-koba-danger' :
                              event.score > 0.5 ? 'bg-koba-warning-muted text-koba-warning' :
                              'bg-koba-accent-muted text-koba-accent'
                            }`}>
                              Score: {(event.score * 100).toFixed(0)}%
                            </span>
                            <p className="text-koba-text-muted text-xs mt-2">
                              {new Date(event.timestamp).toLocaleString()}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Cognitive Tripwires Tab */}
            {selectedTab === 'cognitive' && (
              <div className="space-y-6">
                {/* Tripwire Status */}
                <div className="koba-card">
                  <h2 className="text-lg font-semibold text-koba-text mb-4">Monitor Status</h2>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {Object.entries(tripwireStatus).length === 0 ? (
                      <p className="text-koba-text-secondary col-span-3">No behavior monitors configured.</p>
                    ) : (
                      Object.entries(tripwireStatus).map(([name, status]: [string, any]) => (
                        <div key={name} className="bg-koba-bg-elevated rounded-xl p-4 border border-koba-border">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-koba-text font-medium">{name}</span>
                            <span className={`koba-badge ${
                              status?.triggered ? 'bg-koba-danger-muted text-koba-danger' : 'bg-koba-success-muted text-koba-success'
                            }`}>
                              {status?.triggered ? 'TRIGGERED' : 'CLEAR'}
                            </span>
                          </div>
                          <p className="text-koba-text-secondary text-sm">{status?.description || 'Monitoring active'}</p>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Cognitive Alerts */}
                <div className="koba-card overflow-hidden p-0">
                  <div className="p-6 border-b border-koba-border">
                    <h2 className="text-lg font-semibold text-koba-text">Cognitive Alerts</h2>
                    <p className="text-koba-text-secondary text-sm mt-1">
                      Intent verification and behavior pattern analysis
                    </p>
                  </div>
                  {cognitiveAlerts.length === 0 ? (
                    <div className="p-12 text-center">
                      <div className="w-16 h-16 bg-koba-success-muted rounded-2xl flex items-center justify-center mx-auto mb-4">
                        <svg className="w-8 h-8 text-koba-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                      <h3 className="text-xl font-medium text-koba-text mb-2">No Cognitive Alerts</h3>
                      <p className="text-koba-text-secondary">All clear — no intent-action mismatches detected.</p>
                    </div>
                  ) : (
                    <div className="divide-y divide-koba-border">
                      {cognitiveAlerts.map((alert, idx) => (
                        <div key={idx} className="p-4 hover:bg-koba-bg-elevated/50 transition-colors">
                          <div className="flex items-start gap-4">
                            <div className="w-10 h-10 rounded-xl bg-koba-danger-muted flex items-center justify-center">
                              <svg className="w-5 h-5 text-koba-danger" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                              </svg>
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <span className="text-koba-text font-medium">{alert.type}</span>
                                <span className={`koba-badge border ${
                                  SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.medium
                                }`}>
                                  {alert.severity?.toUpperCase()}
                                </span>
                              </div>
                              {alert.stated_intent && (
                                <div className="mb-2">
                                  <p className="text-koba-text-secondary text-sm">Stated Intent:</p>
                                  <p className="text-koba-text text-sm italic">"{alert.stated_intent}"</p>
                                </div>
                              )}
                              {alert.actual_action && (
                                <div className="mb-2">
                                  <p className="text-koba-text-secondary text-sm">Actual Action:</p>
                                  <p className="text-koba-danger text-sm">{alert.actual_action}</p>
                                </div>
                              )}
                              <p className="text-koba-text-muted text-xs">
                                {new Date(alert.timestamp).toLocaleString()}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Sessions Tab */}
            {selectedTab === 'sessions' && (
              <div className="koba-card overflow-hidden p-0">
                <div className="p-6 border-b border-koba-border">
                  <h2 className="text-lg font-semibold text-koba-text">Active Sessions</h2>
                  <p className="text-koba-text-secondary text-sm mt-1">
                    Monitor and manage agent session states
                  </p>
                </div>
                <div className="p-6">
                  {/* Session list using memoized data */}
                  {sessionData.length === 0 ? (
                    <div className="text-center py-8">
                      <div className="w-16 h-16 bg-koba-bg-elevated rounded-2xl flex items-center justify-center mx-auto mb-4">
                        <svg className="w-8 h-8 text-koba-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                        </svg>
                      </div>
                      <h3 className="text-lg font-medium text-koba-text mb-2">No Active Sessions</h3>
                      <p className="text-koba-text-secondary">No sessions with recorded events.</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {sessionData.map(({ sessionId, events: sessionEvents, maxScore }) => (
                        <div key={sessionId} className="bg-koba-bg-elevated rounded-xl p-4 border border-koba-border hover:border-koba-border-light transition-colors">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-koba-text font-mono text-sm">{sessionId}</p>
                              <p className="text-koba-text-muted text-sm mt-1">
                                {sessionEvents.length} event(s) • Max score: {(maxScore * 100).toFixed(0)}%
                              </p>
                            </div>
                            <div className="flex items-center gap-3">
                              <span className={`koba-badge ${
                                maxScore > 0.8 ? 'bg-koba-danger-muted text-koba-danger' :
                                maxScore > 0.5 ? 'bg-koba-warning-muted text-koba-warning' :
                                'bg-koba-success-muted text-koba-success'
                              }`}>
                                {maxScore > 0.8 ? 'HIGH RISK' : maxScore > 0.5 ? 'ELEVATED' : 'NORMAL'}
                              </span>
                              {hasPermission('system:admin') && (
                                <button
                                  onClick={() => resetSession(sessionId)}
                                  className="koba-btn koba-btn-secondary text-sm py-1 px-3"
                                >
                                  Reset
                                </button>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </AppShell>
  );
}
