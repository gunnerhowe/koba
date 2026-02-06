'use client';

import { useEffect, useState } from 'react';
import AppShell from '@/components/AppShell';
import { useAuth } from '@/lib/auth';
import { API_BASE } from '@/lib/api';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

// Integration definitions - these are the supported integrations
const AVAILABLE_INTEGRATIONS = [
  {
    id: 'clawdbot',
    name: 'ClawdBot',
    description: 'Personal AI assistant for WhatsApp, Telegram, Discord, Slack, and more',
    icon: '🦞',
    category: 'ai-agent',
    docsUrl: 'https://docs.clawd.bot',
    features: ['Tool governance', 'Audit logging', 'Policy enforcement'],
    installMethod: 'plugin',
  },
  {
    id: 'claude-code',
    name: 'Claude Code',
    description: "Anthropic's CLI coding assistant with MCP support",
    icon: '🤖',
    category: 'ai-agent',
    docsUrl: 'https://docs.anthropic.com/claude-code',
    features: ['MCP server integration', 'Tool governance', 'Audit logging'],
    installMethod: 'mcp',
  },
  {
    id: 'openai-agents',
    name: 'OpenAI Agents',
    description: 'OpenAI Assistants API and GPT-based agents',
    icon: '🧠',
    category: 'ai-agent',
    docsUrl: 'https://platform.openai.com/docs/assistants',
    features: ['Function call governance', 'Usage tracking', 'Policy enforcement'],
    installMethod: 'webhook',
  },
  {
    id: 'langchain',
    name: 'LangChain',
    description: 'Popular framework for building LLM applications',
    icon: '🦜',
    category: 'framework',
    docsUrl: 'https://python.langchain.com',
    features: ['Tool wrapper', 'Chain governance', 'Agent monitoring'],
    installMethod: 'sdk',
  },
  {
    id: 'crewai',
    name: 'CrewAI',
    description: 'Framework for orchestrating AI agent teams',
    icon: '👥',
    category: 'framework',
    docsUrl: 'https://docs.crewai.com',
    features: ['Multi-agent governance', 'Task monitoring', 'Audit trails'],
    installMethod: 'sdk',
  },
  {
    id: 'autogen',
    name: 'AutoGen',
    description: 'Microsoft framework for multi-agent conversations',
    icon: '🔄',
    category: 'framework',
    docsUrl: 'https://microsoft.github.io/autogen',
    features: ['Conversation governance', 'Agent monitoring', 'Policy enforcement'],
    installMethod: 'sdk',
  },
  {
    id: 'custom-webhook',
    name: 'Custom Webhook',
    description: 'Connect any system via webhook integration',
    icon: '🔗',
    category: 'custom',
    docsUrl: null,
    features: ['Universal compatibility', 'Custom configuration', 'Flexible setup'],
    installMethod: 'webhook',
  },
  {
    id: 'custom-sdk',
    name: 'Custom SDK',
    description: 'Integrate using the Koba Python or JavaScript SDK',
    icon: '📦',
    category: 'custom',
    docsUrl: null,
    features: ['Full API access', 'Custom policies', 'Deep integration'],
    installMethod: 'sdk',
  },
];

interface Integration {
  id: string;
  name: string;
  type: string;
  status: 'connected' | 'disconnected' | 'pending' | 'error';
  config: Record<string, unknown>;
  created_at: string;
  last_activity?: string;
  stats?: {
    total_calls: number;
    allowed: number;
    denied: number;
  };
}

interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info';
}

export default function IntegrationsPage() {
  const { user, token, hasPermission } = useAuth();
  const [loading, setLoading] = useState(true);
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [selectedIntegration, setSelectedIntegration] = useState<string | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [addingIntegration, setAddingIntegration] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});

  const showToast = (message: string, type: 'success' | 'error' | 'info') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4000);
  };

  useEffect(() => {
    if (!user) return;
    loadIntegrations();
  }, [user, token]);

  const loadIntegrations = async () => {
    try {
      const res = await fetch(`${API_BASE}/v1/integrations`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (res.ok) {
        const data = await res.json();
        setIntegrations(data.integrations || []);
      }
    } catch (error) {
      console.error('Failed to load integrations:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddIntegration = async (integrationId: string) => {
    setAddingIntegration(integrationId);
    const integration = AVAILABLE_INTEGRATIONS.find(i => i.id === integrationId);
    if (!integration) return;

    try {
      const res = await fetch(`${API_BASE}/v1/integrations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          type: integrationId,
          name: integration.name,
          config: configValues,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        showToast(`${integration.name} integration added successfully!`, 'success');
        setShowAddModal(false);
        setConfigValues({});
        loadIntegrations();

        // If there are setup instructions, show them
        if (data.setup_instructions) {
          setSelectedIntegration(data.integration.id);
        }
      } else {
        const error = await res.json();
        showToast(error.detail || 'Failed to add integration', 'error');
      }
    } catch (error) {
      showToast('Failed to connect to server', 'error');
    } finally {
      setAddingIntegration(null);
    }
  };

  const handleRemoveIntegration = async (integrationId: string) => {
    if (!confirm('Are you sure you want to remove this integration?')) return;

    try {
      const res = await fetch(`${API_BASE}/v1/integrations/${integrationId}`, {
        method: 'DELETE',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });

      if (res.ok) {
        showToast('Integration removed', 'success');
        setIntegrations(prev => prev.filter(i => i.id !== integrationId));
        if (selectedIntegration === integrationId) {
          setSelectedIntegration(null);
        }
      } else {
        showToast('Failed to remove integration', 'error');
      }
    } catch (error) {
      showToast('Failed to connect to server', 'error');
    }
  };

  const handleTestConnection = async (integrationId: string) => {
    try {
      const res = await fetch(`${API_BASE}/v1/integrations/${integrationId}/test`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });

      if (res.ok) {
        const data = await res.json();
        if (data.success) {
          showToast('Connection successful!', 'success');
        } else {
          showToast(`Connection failed: ${data.error}`, 'error');
        }
      } else {
        showToast('Test failed', 'error');
      }
    } catch (error) {
      showToast('Failed to test connection', 'error');
    }
  };

  const handleAutoInstall = async (integrationId: string) => {
    const integration = integrations.find(i => i.id === integrationId);
    if (!integration) return;

    showToast(`Installing ${integration.name} plugin...`, 'info');

    try {
      const res = await fetch(`${API_BASE}/v1/integrations/${integrationId}/auto-install`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });

      if (res.ok) {
        const data = await res.json();
        showToast(data.message || 'Plugin installed successfully!', 'success');
        loadIntegrations();
      } else {
        const error = await res.json();
        showToast(error.detail || 'Auto-install failed', 'error');
      }
    } catch (error) {
      showToast('Failed to auto-install', 'error');
    }
  };

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      connected: 'bg-success/20 text-success',
      disconnected: 'bg-text-muted/20 text-text-muted',
      pending: 'bg-warning/20 text-warning',
      error: 'bg-danger/20 text-danger',
    };
    return styles[status] || styles.disconnected;
  };

  const selectedIntegrationData = selectedIntegration
    ? integrations.find(i => i.id === selectedIntegration)
    : null;

  const selectedIntegrationMeta = selectedIntegrationData
    ? AVAILABLE_INTEGRATIONS.find(i => i.id === selectedIntegrationData.type)
    : null;

  return (
    <AppShell>
      {/* Toast notifications */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map(toast => (
          <div
            key={toast.id}
            className={`px-4 py-3 rounded-lg shadow-lg transform transition-all duration-300 ${
              toast.type === 'success'
                ? 'bg-success text-white'
                : toast.type === 'error'
                ? 'bg-danger text-white'
                : 'bg-info text-white'
            }`}
          >
            {toast.message}
          </div>
        ))}
      </div>

      <div className="flex h-full">
        {/* Main content */}
        <div className={`flex-1 p-6 overflow-auto ${selectedIntegration ? 'pr-0' : ''}`}>
          <div className="flex items-center justify-between mb-6">
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-2xl font-bold text-text">Integrations</h1>
                <HelpButton content={helpContent.integrations} />
              </div>
              <p className="text-text-secondary mt-1">
                Connect Koba to your AI agents and frameworks
              </p>
            </div>
            <button
              onClick={() => setShowAddModal(true)}
              className="koba-btn koba-btn-primary flex items-center gap-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add Integration
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-accent"></div>
            </div>
          ) : integrations.length === 0 ? (
            <div className="koba-card p-12 text-center">
              <div className="text-6xl mb-4">🔌</div>
              <h2 className="text-xl font-semibold text-text mb-2">No integrations yet</h2>
              <p className="text-text-secondary mb-6">
                Connect Koba to your AI agents for full visibility and oversight
              </p>
              <button
                onClick={() => setShowAddModal(true)}
                className="koba-btn koba-btn-primary"
              >
                Add Your First Integration
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {integrations.map(integration => {
                const meta = AVAILABLE_INTEGRATIONS.find(i => i.id === integration.type);
                return (
                  <div
                    key={integration.id}
                    onClick={() => setSelectedIntegration(integration.id)}
                    className={`koba-card p-4 cursor-pointer transition-all hover:border-accent ${
                      selectedIntegration === integration.id ? 'border-accent ring-1 ring-accent' : ''
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-3xl">{meta?.icon || '🔗'}</span>
                        <div>
                          <h3 className="font-semibold text-text">{integration.name}</h3>
                          <span className={`text-xs px-2 py-0.5 rounded-full ${getStatusBadge(integration.status)}`}>
                            {integration.status}
                          </span>
                        </div>
                      </div>
                    </div>
                    {integration.stats && (
                      <div className="mt-4 grid grid-cols-3 gap-2 text-center text-sm">
                        <div>
                          <div className="text-text font-semibold">{integration.stats.total_calls}</div>
                          <div className="text-text-muted text-xs">Total</div>
                        </div>
                        <div>
                          <div className="text-success font-semibold">{integration.stats.allowed}</div>
                          <div className="text-text-muted text-xs">Allowed</div>
                        </div>
                        <div>
                          <div className="text-danger font-semibold">{integration.stats.denied}</div>
                          <div className="text-text-muted text-xs">Denied</div>
                        </div>
                      </div>
                    )}
                    {integration.last_activity && (
                      <div className="mt-3 text-xs text-text-muted">
                        Last activity: {new Date(integration.last_activity).toLocaleString()}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Detail panel */}
        {selectedIntegration && selectedIntegrationData && (
          <div className="w-96 border-l border-border bg-bg-card p-6 overflow-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-text">Integration Details</h2>
              <button
                onClick={() => setSelectedIntegration(null)}
                className="text-text-muted hover:text-text"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="space-y-6">
              <div className="flex items-center gap-4">
                <span className="text-5xl">{selectedIntegrationMeta?.icon || '🔗'}</span>
                <div>
                  <h3 className="text-xl font-bold text-text">{selectedIntegrationData.name}</h3>
                  <span className={`text-sm px-2 py-0.5 rounded-full ${getStatusBadge(selectedIntegrationData.status)}`}>
                    {selectedIntegrationData.status}
                  </span>
                </div>
              </div>

              {selectedIntegrationMeta?.description && (
                <p className="text-text-secondary text-sm">
                  {selectedIntegrationMeta.description}
                </p>
              )}

              <div className="space-y-2">
                <h4 className="text-sm font-medium text-text">Features</h4>
                <ul className="space-y-1">
                  {selectedIntegrationMeta?.features.map((feature, i) => (
                    <li key={i} className="flex items-center gap-2 text-sm text-text-secondary">
                      <svg className="w-4 h-4 text-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      {feature}
                    </li>
                  ))}
                </ul>
              </div>

              {selectedIntegrationData.stats && (
                <div className="space-y-2">
                  <h4 className="text-sm font-medium text-text">Statistics</h4>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-xl font-bold text-text">{selectedIntegrationData.stats.total_calls}</div>
                      <div className="text-xs text-text-muted">Total Calls</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-xl font-bold text-success">{selectedIntegrationData.stats.allowed}</div>
                      <div className="text-xs text-text-muted">Allowed</div>
                    </div>
                    <div className="bg-bg-secondary rounded-lg p-3 text-center">
                      <div className="text-xl font-bold text-danger">{selectedIntegrationData.stats.denied}</div>
                      <div className="text-xs text-text-muted">Denied</div>
                    </div>
                  </div>
                </div>
              )}

              <div className="space-y-2">
                <h4 className="text-sm font-medium text-text">Actions</h4>
                <div className="space-y-2">
                  <button
                    onClick={() => handleTestConnection(selectedIntegrationData.id)}
                    className="w-full koba-btn bg-bg-secondary hover:bg-bg-elevated text-text"
                  >
                    Test Connection
                  </button>
                  {selectedIntegrationMeta?.installMethod === 'plugin' && (
                    <button
                      onClick={() => handleAutoInstall(selectedIntegrationData.id)}
                      className="w-full koba-btn koba-btn-primary"
                    >
                      Auto-Install Plugin
                    </button>
                  )}
                  <button
                    onClick={() => handleRemoveIntegration(selectedIntegrationData.id)}
                    className="w-full koba-btn bg-danger/10 text-danger hover:bg-danger/20"
                  >
                    Remove Integration
                  </button>
                </div>
              </div>

              {selectedIntegrationMeta?.docsUrl && (
                <a
                  href={selectedIntegrationMeta.docsUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block text-center text-accent hover:underline text-sm"
                >
                  View Documentation →
                </a>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Add Integration Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-bg-card rounded-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
            <div className="flex items-center justify-between p-6 border-b border-border">
              <h2 className="text-xl font-bold text-text">Add Integration</h2>
              <button
                onClick={() => {
                  setShowAddModal(false);
                  setConfigValues({});
                }}
                className="text-text-muted hover:text-text"
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="p-6 overflow-auto max-h-[70vh]">
              <div className="mb-6">
                <h3 className="text-sm font-medium text-text-secondary mb-3">AI Agents</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {AVAILABLE_INTEGRATIONS.filter(i => i.category === 'ai-agent').map(integration => (
                    <div
                      key={integration.id}
                      className="koba-card p-4 hover:border-accent transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <span className="text-3xl">{integration.icon}</span>
                        <div className="flex-1">
                          <h4 className="font-semibold text-text">{integration.name}</h4>
                          <p className="text-sm text-text-secondary mt-1">{integration.description}</p>
                          <div className="flex flex-wrap gap-1 mt-2">
                            {integration.features.map((f, i) => (
                              <span key={i} className="text-xs bg-bg-secondary px-2 py-0.5 rounded text-text-muted">
                                {f}
                              </span>
                            ))}
                          </div>
                          <button
                            onClick={() => handleAddIntegration(integration.id)}
                            disabled={addingIntegration === integration.id}
                            className="mt-3 koba-btn koba-btn-primary text-sm py-1.5"
                          >
                            {addingIntegration === integration.id ? 'Connecting...' : 'Connect'}
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mb-6">
                <h3 className="text-sm font-medium text-text-secondary mb-3">Frameworks</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {AVAILABLE_INTEGRATIONS.filter(i => i.category === 'framework').map(integration => (
                    <div
                      key={integration.id}
                      className="koba-card p-4 hover:border-accent transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <span className="text-3xl">{integration.icon}</span>
                        <div className="flex-1">
                          <h4 className="font-semibold text-text">{integration.name}</h4>
                          <p className="text-sm text-text-secondary mt-1">{integration.description}</p>
                          <button
                            onClick={() => handleAddIntegration(integration.id)}
                            disabled={addingIntegration === integration.id}
                            className="mt-3 koba-btn koba-btn-primary text-sm py-1.5"
                          >
                            {addingIntegration === integration.id ? 'Connecting...' : 'Connect'}
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-text-secondary mb-3">Custom</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {AVAILABLE_INTEGRATIONS.filter(i => i.category === 'custom').map(integration => (
                    <div
                      key={integration.id}
                      className="koba-card p-4 hover:border-accent transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <span className="text-3xl">{integration.icon}</span>
                        <div className="flex-1">
                          <h4 className="font-semibold text-text">{integration.name}</h4>
                          <p className="text-sm text-text-secondary mt-1">{integration.description}</p>
                          <button
                            onClick={() => handleAddIntegration(integration.id)}
                            disabled={addingIntegration === integration.id}
                            className="mt-3 koba-btn koba-btn-primary text-sm py-1.5"
                          >
                            {addingIntegration === integration.id ? 'Setting up...' : 'Set Up'}
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}
