'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import AppShell from '@/components/AppShell';
import ReceiptCard from '@/components/ReceiptCard';
import { Receipt, fetchReceipts } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { ChevronLeft, ChevronRight, Search } from 'lucide-react';
import Spinner from '@/components/Spinner';
import EmptyState from '@/components/EmptyState';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

export default function ReceiptsPage() {
  const { user, token, loading: authLoading } = useAuth();
  const router = useRouter();
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const limit = 10;

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await fetchReceipts(page, limit);
        setReceipts(data.entries || []);
        setTotal(data.total || 0);
      } catch (err) {
        console.error('Failed to fetch receipts:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [page]);

  const filteredReceipts = receipts.filter((r) =>
    search === '' ||
    r.receipt_id.toLowerCase().includes(search.toLowerCase()) ||
    r.tool.name.toLowerCase().includes(search.toLowerCase()) ||
    r.agent_id.toLowerCase().includes(search.toLowerCase())
  );

  const totalPages = Math.ceil(total / limit);

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-koba-text">Receipts</h1>
              <HelpButton content={helpContent.receipts} />
            </div>
            <p className="text-koba-text-secondary mt-1">
              Browse all Signed Action Receipts
            </p>
          </div>

          {/* Search */}
          <div className="mb-6">
            <div className="relative">
              <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-koba-text-secondary" />
              <input
                type="text"
                placeholder="Search by receipt ID, tool, or agent..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full bg-koba-bg-card border border-koba-border rounded-lg pl-12 pr-4 py-3 text-koba-text placeholder-koba-text-secondary focus:outline-none focus:border-koba-accent"
              />
            </div>
          </div>

          {/* Receipts List */}
          {loading ? (
            <Spinner size="lg" className="h-64" />
          ) : (
            <div className="space-y-3">
              {filteredReceipts.length === 0 ? (
                <EmptyState title="No receipts found" description="Action receipts will appear here once agents start executing tools" />
              ) : (
                filteredReceipts.map((receipt) => (
                  <ReceiptCard key={receipt.receipt_id} receipt={receipt} compact />
                ))
              )}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="mt-8 flex items-center justify-between">
              <p className="text-koba-text-secondary text-sm">
                Showing {page * limit + 1} - {Math.min((page + 1) * limit, total)} of {total}
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage(Math.max(0, page - 1))}
                  disabled={page === 0}
                  className="p-2 rounded-lg bg-koba-bg-card border border-koba-border text-koba-text disabled:opacity-50 disabled:cursor-not-allowed hover:border-koba-accent/30"
                >
                  <ChevronLeft className="w-5 h-5" />
                </button>
                <span className="px-4 py-2 text-koba-text-secondary text-sm">
                  Page {page + 1} of {totalPages}
                </span>
                <button
                  onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                  disabled={page >= totalPages - 1}
                  className="p-2 rounded-lg bg-koba-bg-card border border-koba-border text-koba-text disabled:opacity-50 disabled:cursor-not-allowed hover:border-koba-accent/30"
                >
                  <ChevronRight className="w-5 h-5" />
                </button>
              </div>
            </div>
          )}
        </div>
      </AppShell>
  );
}
