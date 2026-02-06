'use client';

import { useRequireAuth } from '@/lib/auth';
import AppShell from '@/components/AppShell';
import Spinner from '@/components/Spinner';

export default function AnchorsPage() {
  const { loading: authLoading } = useRequireAuth();

  if (authLoading) {
    return (
      <AppShell>
        <Spinner size="lg" className="h-64" />
      </AppShell>
    );
  }

  return (
    <AppShell>
      <div className="max-w-2xl mx-auto text-center py-20">
        <div className="w-20 h-20 bg-koba-accent/20 rounded-2xl flex items-center justify-center mx-auto mb-6">
          <svg className="w-10 h-10 text-koba-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
          </svg>
        </div>
        <h1 className="text-2xl font-bold text-koba-text mb-3">External Anchoring</h1>
        <p className="text-koba-text-secondary mb-2">
          This feature publishes your audit proofs to a public ledger for independent, third-party verification.
        </p>
        <p className="text-koba-text-muted text-sm mb-8">
          Your records are already protected by local cryptographic proofs (Merkle tree + signed receipts).
          External anchoring adds an extra layer for compliance and regulatory requirements.
        </p>
        <div className="inline-flex items-center gap-2 px-4 py-2 bg-koba-accent/10 border border-koba-accent/20 rounded-full">
          <span className="text-koba-accent text-sm font-medium">Coming in Koba Pro</span>
        </div>
      </div>
    </AppShell>
  );
}
