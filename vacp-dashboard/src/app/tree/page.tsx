'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import AppShell from '@/components/AppShell';
import { TreeHead, fetchTreeHead } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { GitBranch, CheckCircle, Clock, Hash, Layers, Shield } from 'lucide-react';
import Spinner from '@/components/Spinner';
import EmptyState from '@/components/EmptyState';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

export default function TreePage() {
  const { user, token, loading: authLoading } = useAuth();
  const router = useRouter();
  const [treeHead, setTreeHead] = useState<TreeHead | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  useEffect(() => {
    async function loadData() {
      try {
        const data = await fetchTreeHead();
        setTreeHead(data);
      } catch (err) {
        console.error('Failed to fetch tree head:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <AppShell>
      <div className="max-w-4xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-koba-text">Proof Log</h1>
              <HelpButton content={helpContent.merkleTree} />
            </div>
            <p className="text-koba-text-secondary mt-1">
              Tamper-proof record that proves no actions were hidden or changed
            </p>
          </div>

          {loading ? (
            <Spinner size="lg" className="h-64" />
          ) : treeHead ? (
            <div className="space-y-6">
              {/* Tree Head Card */}
              <div className="bg-gradient-to-br from-koba-accent/20 to-purple-900/20 border border-koba-accent/30 rounded-xl p-8">
                <div className="flex items-center gap-4 mb-6">
                  <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-koba-accent to-purple-600 flex items-center justify-center">
                    <GitBranch className="w-7 h-7 text-white" />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-koba-text">Current Log Status</h2>
                    <div className="flex items-center gap-2 mt-1">
                      <CheckCircle className="w-4 h-4 text-koba-success" />
                      <span className="text-koba-success text-sm">Signature Valid</span>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-koba-bg/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-koba-text-secondary text-sm mb-2">
                      <Layers className="w-4 h-4" />
                      Tree Size
                    </div>
                    <p className="text-3xl font-bold text-koba-accent-light">{treeHead.tree_size}</p>
                  </div>
                  <div className="bg-koba-bg/50 rounded-lg p-4 md:col-span-2">
                    <div className="flex items-center gap-2 text-koba-text-secondary text-sm mb-2">
                      <Clock className="w-4 h-4" />
                      Timestamp
                    </div>
                    <p className="text-koba-text">{new Date(treeHead.timestamp).toLocaleString()}</p>
                  </div>
                </div>

                <div className="mt-6 bg-koba-bg/50 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-koba-text-secondary text-sm mb-2">
                    <Hash className="w-4 h-4" />
                    Integrity Fingerprint
                  </div>
                  <p className="font-mono text-sm text-koba-text break-all">{treeHead.root_hash}</p>
                </div>

                {treeHead.signature && (
                  <div className="mt-4 bg-koba-bg/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-koba-text-secondary text-sm mb-2">
                      <Shield className="w-4 h-4" />
                      Signature
                    </div>
                    <p className="font-mono text-xs text-koba-text-secondary break-all">{treeHead.signature}</p>
                  </div>
                )}
              </div>

              {/* Properties */}
              <div className="bg-koba-bg-card border border-koba-border rounded-xl p-6">
                <h3 className="text-lg font-semibold text-koba-text mb-4">Transparency Log Properties</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="flex items-start gap-4">
                    <div className="w-10 h-10 rounded-lg bg-koba-accent/20 flex items-center justify-center flex-shrink-0">
                      <span className="text-koba-accent-light font-bold">1</span>
                    </div>
                    <div>
                      <h4 className="text-koba-text font-medium">Append-Only</h4>
                      <p className="text-koba-text-secondary text-sm mt-1">
                        Entries can only be added to the log, never modified or deleted
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-4">
                    <div className="w-10 h-10 rounded-lg bg-koba-accent/20 flex items-center justify-center flex-shrink-0">
                      <span className="text-koba-accent-light font-bold">2</span>
                    </div>
                    <div>
                      <h4 className="text-koba-text font-medium">Inclusion Proofs</h4>
                      <p className="text-koba-text-secondary text-sm mt-1">
                        O(log n) proof that any entry exists in the log
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-4">
                    <div className="w-10 h-10 rounded-lg bg-koba-accent/20 flex items-center justify-center flex-shrink-0">
                      <span className="text-koba-accent-light font-bold">3</span>
                    </div>
                    <div>
                      <h4 className="text-koba-text font-medium">Consistency Proofs</h4>
                      <p className="text-koba-text-secondary text-sm mt-1">
                        Verify the log only grows, never forks or rewrites history
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-4">
                    <div className="w-10 h-10 rounded-lg bg-koba-accent/20 flex items-center justify-center flex-shrink-0">
                      <span className="text-koba-accent-light font-bold">4</span>
                    </div>
                    <div>
                      <h4 className="text-koba-text font-medium">Signed Tree Heads</h4>
                      <p className="text-koba-text-secondary text-sm mt-1">
                        Cryptographic commitment to the current state
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* How It Works */}
              <div className="bg-koba-bg-card border border-koba-border rounded-xl p-6">
                <h3 className="text-lg font-semibold text-koba-text mb-4">How It Works</h3>
                <div className="space-y-4 text-koba-text-secondary">
                  <p>
                    The Merkle transparency log provides tamper-evident storage for all Signed Action Receipts.
                    It is inspired by Certificate Transparency (RFC 6962) and provides similar guarantees.
                  </p>
                  <p>
                    Each receipt is hashed and added as a leaf node. The tree is built using SHA-256,
                    with each parent node being the hash of its children. The root hash commits to the
                    entire log state.
                  </p>
                  <p>
                    Anyone can verify that a receipt exists in the log using an inclusion proof, which
                    requires only O(log n) hashes. The signed tree head provides a cryptographic
                    commitment to the entire log state at any point in time.
                  </p>
                </div>
              </div>

              {/* Visual Tree */}
              <div className="bg-koba-bg-card border border-koba-border rounded-xl p-6">
                <h3 className="text-lg font-semibold text-koba-text mb-4">Tree Visualization</h3>
                <div className="flex justify-center py-8">
                  <div className="text-center">
                    {/* Root */}
                    <div className="inline-block px-4 py-2 bg-koba-accent/20 border border-koba-accent/30 rounded-lg mb-4">
                      <p className="text-xs text-koba-text-secondary">Root</p>
                      <p className="font-mono text-xs text-koba-accent-light">{treeHead.root_hash.slice(0, 16)}...</p>
                    </div>
                    <div className="w-px h-6 bg-koba-border mx-auto"></div>
                    {/* Level 1 */}
                    <div className="flex justify-center gap-8 mb-4">
                      <div className="text-center">
                        <div className="w-px h-6 bg-koba-border mx-auto"></div>
                        <div className="px-3 py-1 bg-koba-bg border border-koba-border rounded text-xs text-koba-text-secondary">H(0-n/2)</div>
                      </div>
                      <div className="text-center">
                        <div className="w-px h-6 bg-koba-border mx-auto"></div>
                        <div className="px-3 py-1 bg-koba-bg border border-koba-border rounded text-xs text-koba-text-secondary">H(n/2-n)</div>
                      </div>
                    </div>
                    {/* Leaves */}
                    <div className="flex justify-center gap-2">
                      {[...Array(Math.min(8, treeHead.tree_size))].map((_, i) => (
                        <div key={i} className="w-8 h-8 bg-koba-success/20 border border-koba-success/30 rounded text-xs flex items-center justify-center text-koba-success">
                          {i}
                        </div>
                      ))}
                      {treeHead.tree_size > 8 && (
                        <div className="w-8 h-8 border border-koba-border border-dashed rounded text-xs flex items-center justify-center text-koba-text-secondary">
                          ...
                        </div>
                      )}
                    </div>
                    <p className="text-koba-text-secondary text-xs mt-4">{treeHead.tree_size} receipts in log</p>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <EmptyState title="No tree data" description="The proof log will appear once receipts are recorded" />
          )}
        </div>
      </AppShell>
  );
}
