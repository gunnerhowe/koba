'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import AppShell from '@/components/AppShell';
import { verifyReceipt, VerifyResult } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { ShieldCheck, CheckCircle, XCircle, Search, AlertTriangle } from 'lucide-react';
import Link from 'next/link';
import Spinner from '@/components/Spinner';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

export default function VerifyPage() {
  const { user, token, loading: authLoading } = useAuth();
  const router = useRouter();
  const [receiptId, setReceiptId] = useState('');
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!receiptId.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await verifyReceipt(receiptId.trim());
      setResult(data);
    } catch (err) {
      setError('Failed to verify receipt. Make sure the receipt ID is correct.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AppShell>
      <div className="max-w-2xl mx-auto">
          {/* Header */}
          <div className="mb-8 text-center">
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-koba-accent to-purple-600 flex items-center justify-center mx-auto mb-4">
              <ShieldCheck className="w-8 h-8 text-white" />
            </div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-koba-text">Verify Receipt</h1>
              <HelpButton content={helpContent.verify} />
            </div>
            <p className="text-koba-text-secondary mt-2">
              Verify the cryptographic signature and Merkle proof of any Signed Action Receipt
            </p>
          </div>

          {/* Verification Form */}
          <form onSubmit={handleVerify} className="mb-8">
            <div className="bg-koba-bg-card border border-koba-border rounded-xl p-6">
              <label className="block text-koba-text-secondary text-sm mb-2">
                Receipt ID
              </label>
              <div className="flex gap-3">
                <input
                  type="text"
                  value={receiptId}
                  onChange={(e) => setReceiptId(e.target.value)}
                  placeholder="Enter receipt ID..."
                  className="flex-1 bg-koba-bg border border-koba-border rounded-lg px-4 py-3 text-koba-text placeholder-koba-text-secondary focus:outline-none focus:border-koba-accent font-mono text-sm"
                />
                <button
                  type="submit"
                  disabled={loading || !receiptId.trim()}
                  className="px-6 py-3 bg-koba-accent text-white rounded-lg font-medium hover:bg-koba-accent-light transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {loading ? (
                    <Spinner size="sm" />
                  ) : (
                    <>
                      <Search className="w-5 h-5" />
                      Verify
                    </>
                  )}
                </button>
              </div>
            </div>
          </form>

          {/* Error */}
          {error && (
            <div className="bg-koba-danger/20 border border-koba-danger/30 rounded-xl p-6 mb-6 flex items-center gap-4">
              <AlertTriangle className="w-6 h-6 text-koba-danger flex-shrink-0" />
              <p className="text-koba-danger">{error}</p>
            </div>
          )}

          {/* Result */}
          {result && (
            <div className="space-y-6 fade-in">
              {/* Overall Status */}
              <div className={`rounded-xl p-8 text-center ${
                result.valid ? 'bg-koba-success/20 border border-koba-success/30' : 'bg-koba-danger/20 border border-koba-danger/30'
              }`}>
                <div className={`w-20 h-20 rounded-full mx-auto mb-4 flex items-center justify-center ${
                  result.valid ? 'bg-koba-success/30' : 'bg-koba-danger/30'
                }`}>
                  {result.valid ? (
                    <CheckCircle className="w-10 h-10 text-koba-success" />
                  ) : (
                    <XCircle className="w-10 h-10 text-koba-danger" />
                  )}
                </div>
                <h2 className={`text-2xl font-bold ${result.valid ? 'text-koba-success' : 'text-koba-danger'}`}>
                  {result.valid ? 'Verification Passed' : 'Verification Failed'}
                </h2>
                <p className="text-koba-text-secondary mt-2">
                  {result.valid
                    ? 'This receipt is cryptographically valid and exists in the transparency log.'
                    : 'This receipt failed verification checks.'}
                </p>
              </div>

              {/* Detailed Results */}
              <div className="bg-koba-bg-card border border-koba-border rounded-xl overflow-hidden">
                <div className="p-6 border-b border-koba-border">
                  <h3 className="text-lg font-semibold text-koba-text">Verification Details</h3>
                </div>
                <div className="divide-y divide-koba-border">
                  <div className="p-6 flex items-center justify-between">
                    <div>
                      <p className="text-koba-text font-medium">Digital Signature</p>
                      <p className="text-koba-text-secondary text-sm">Ed25519 signature verification</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {result.signature_valid ? (
                        <>
                          <CheckCircle className="w-5 h-5 text-koba-success" />
                          <span className="text-koba-success font-medium">Valid</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-5 h-5 text-koba-danger" />
                          <span className="text-koba-danger font-medium">Invalid</span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="p-6 flex items-center justify-between">
                    <div>
                      <p className="text-koba-text font-medium">Merkle Proof</p>
                      <p className="text-koba-text-secondary text-sm">Inclusion proof in transparency log</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {result.proof_valid ? (
                        <>
                          <CheckCircle className="w-5 h-5 text-koba-success" />
                          <span className="text-koba-success font-medium">Verified</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-5 h-5 text-koba-danger" />
                          <span className="text-koba-danger font-medium">Not Verified</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* View Full Receipt */}
              {result.receipt && (
                <div className="text-center">
                  <Link
                    href={`/receipts/${result.receipt.receipt_id}`}
                    className="inline-flex items-center gap-2 text-koba-accent-light hover:underline"
                  >
                    View Full Receipt Details
                  </Link>
                </div>
              )}
            </div>
          )}

          {/* Info Box */}
          <div className="mt-8 bg-koba-bg-card border border-koba-border rounded-xl p-6">
            <h3 className="text-koba-text font-semibold mb-3">How Verification Works</h3>
            <ul className="space-y-2 text-koba-text-secondary text-sm">
              <li className="flex items-start gap-2">
                <span className="text-koba-accent">1.</span>
                <span>The receipt's Ed25519 signature is verified against the issuer's public key</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-koba-accent">2.</span>
                <span>The Merkle inclusion proof is validated against the current tree root</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-koba-accent">3.</span>
                <span>Both checks must pass for the receipt to be considered valid</span>
              </li>
            </ul>
          </div>
        </div>
      </AppShell>
  );
}
