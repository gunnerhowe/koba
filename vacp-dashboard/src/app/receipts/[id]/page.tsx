'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import AppShell from '@/components/AppShell';
import { Receipt, fetchReceipt, verifyReceipt, VerifyResult } from '@/lib/api';
import { CheckCircle, XCircle, Clock, ShieldCheck, GitBranch, ArrowLeft, Copy, Check } from 'lucide-react';
import Link from 'next/link';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

const decisionStyles = {
  allow: { bg: 'bg-koba-success/20', border: 'border-koba-success/30', text: 'text-koba-success', icon: CheckCircle, label: 'ALLOWED' },
  deny: { bg: 'bg-koba-danger/20', border: 'border-koba-danger/30', text: 'text-koba-danger', icon: XCircle, label: 'DENIED' },
  pending: { bg: 'bg-koba-warning/20', border: 'border-koba-warning/30', text: 'text-koba-warning', icon: Clock, label: 'PENDING' },
};

export default function ReceiptDetailPage() {
  const params = useParams();
  const id = params.id as string;

  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [proof, setProof] = useState<any>(null);
  const [verification, setVerification] = useState<VerifyResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function loadData() {
      try {
        const data = await fetchReceipt(id);
        setReceipt(data.receipt);
        setProof(data.proof);

        const verifyData = await verifyReceipt(id);
        setVerification(verifyData);
      } catch (err) {
        console.error('Failed to fetch receipt:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [id]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <AppShell>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-koba-accent"></div>
        </div>
      </AppShell>
    );
  }

  if (!receipt) {
    return (
      <AppShell>
        <div className="max-w-4xl mx-auto">
          <div className="bg-koba-danger/20 border border-koba-danger/30 rounded-xl p-8 text-center">
            <XCircle className="w-12 h-12 mx-auto mb-4 text-koba-danger" />
            <h1 className="text-xl font-bold text-koba-text">Receipt Not Found</h1>
            <p className="text-koba-text-secondary mt-2">The requested receipt does not exist.</p>
            <Link href="/receipts" className="inline-block mt-4 text-koba-accent-light hover:underline">
              Back to Receipts
            </Link>
          </div>
        </div>
      </AppShell>
    );
  }

  const style = decisionStyles[receipt.policy.decision] || decisionStyles.deny;
  const Icon = style.icon;
  const timestamp = new Date(receipt.timestamp).toLocaleString();

  return (
    <AppShell>
      <div className="max-w-4xl mx-auto">
        {/* Back Button */}
          <Link
            href="/receipts"
            className="inline-flex items-center gap-2 text-koba-text-secondary hover:text-koba-text mb-6"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Receipts
          </Link>

          {/* Header Card */}
          <div className={`${style.bg} ${style.border} border rounded-xl p-6 mb-6`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`w-14 h-14 rounded-xl ${style.bg} border ${style.border} flex items-center justify-center`}>
                  <Icon className={`w-8 h-8 ${style.text}`} />
                </div>
                <div>
                  <div className="flex items-center gap-3">
                    <h1 className="text-2xl font-bold text-koba-text">{receipt.tool.name}</h1>
                    <HelpButton content={helpContent.receiptDetail} />
                  </div>
                  <p className={`${style.text} font-semibold`}>{style.label}</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-koba-text-secondary text-sm">Executed at</p>
                <p className="text-koba-text">{timestamp}</p>
              </div>
            </div>
          </div>

          {/* Verification Status */}
          {verification && (
            <div className="bg-koba-bg-card border border-koba-border rounded-xl p-6 mb-6">
              <div className="flex items-center gap-3 mb-4">
                <ShieldCheck className="w-6 h-6 text-koba-accent-light" />
                <h2 className="text-lg font-semibold text-koba-text">Verification Status</h2>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex items-center gap-3">
                  {verification.signature_valid ? (
                    <CheckCircle className="w-5 h-5 text-koba-success" />
                  ) : (
                    <XCircle className="w-5 h-5 text-koba-danger" />
                  )}
                  <div>
                    <p className="text-koba-text">Signature</p>
                    <p className={verification.signature_valid ? 'text-koba-success' : 'text-koba-danger'}>
                      {verification.signature_valid ? 'Valid' : 'Invalid'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {verification.proof_valid ? (
                    <CheckCircle className="w-5 h-5 text-koba-success" />
                  ) : (
                    <XCircle className="w-5 h-5 text-koba-danger" />
                  )}
                  <div>
                    <p className="text-koba-text">Merkle Proof</p>
                    <p className={verification.proof_valid ? 'text-koba-success' : 'text-koba-danger'}>
                      {verification.proof_valid ? 'Verified' : 'Not Verified'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Receipt Details */}
          <div className="bg-koba-bg-card border border-koba-border rounded-xl overflow-hidden mb-6">
            <div className="p-6 border-b border-koba-border">
              <h2 className="text-lg font-semibold text-koba-text">Receipt Details</h2>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Receipt ID</p>
                <div className="flex items-center gap-2">
                  <p className="font-mono text-sm text-koba-text break-all flex-1">{receipt.receipt_id}</p>
                  <button
                    onClick={() => copyToClipboard(receipt.receipt_id)}
                    className="p-2 rounded hover:bg-koba-bg transition-colors"
                  >
                    {copied ? <Check className="w-4 h-4 text-koba-success" /> : <Copy className="w-4 h-4 text-koba-text-secondary" />}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Agent ID</p>
                  <p className="text-koba-text">{receipt.agent_id}</p>
                </div>
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Tenant ID</p>
                  <p className="text-koba-text">{receipt.tenant_id}</p>
                </div>
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Session ID</p>
                  <p className="text-koba-text">{receipt.session_id}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Tool Info */}
          <div className="bg-koba-bg-card border border-koba-border rounded-xl overflow-hidden mb-6">
            <div className="p-6 border-b border-koba-border">
              <h2 className="text-lg font-semibold text-koba-text">Tool Information</h2>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Tool ID</p>
                  <p className="text-koba-text font-mono">{receipt.tool.id}</p>
                </div>
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Tool Name</p>
                  <p className="text-koba-text">{receipt.tool.name}</p>
                </div>
              </div>
              <div>
                <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Request Hash</p>
                <p className="font-mono text-sm text-koba-text break-all">{receipt.tool.request_hash}</p>
              </div>
              {receipt.tool.response_hash && (
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Response Hash</p>
                  <p className="font-mono text-sm text-koba-text break-all">{receipt.tool.response_hash}</p>
                </div>
              )}
            </div>
          </div>

          {/* Policy Info */}
          <div className="bg-koba-bg-card border border-koba-border rounded-xl overflow-hidden mb-6">
            <div className="p-6 border-b border-koba-border">
              <h2 className="text-lg font-semibold text-koba-text">Policy Evaluation</h2>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Bundle ID</p>
                  <p className="text-koba-text">{receipt.policy.bundle_id}</p>
                </div>
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Decision</p>
                  <span className={`px-3 py-1 rounded ${style.bg} ${style.text} font-semibold`}>
                    {style.label}
                  </span>
                </div>
              </div>
              <div>
                <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Policy Hash</p>
                <p className="font-mono text-sm text-koba-text break-all">{receipt.policy.policy_hash}</p>
              </div>
              {receipt.policy.rules_matched.length > 0 && (
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-2">Rules Matched</p>
                  <div className="flex flex-wrap gap-2">
                    {receipt.policy.rules_matched.map((rule) => (
                      <span key={rule} className="px-3 py-1 bg-koba-bg rounded-lg text-sm text-koba-text border border-koba-border">
                        {rule}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Log Position */}
          <div className="bg-koba-bg-card border border-koba-border rounded-xl overflow-hidden mb-6">
            <div className="p-6 border-b border-koba-border flex items-center gap-3">
              <GitBranch className="w-5 h-5 text-koba-accent-light" />
              <h2 className="text-lg font-semibold text-koba-text">Log Position</h2>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Log Index</p>
                <p className="text-2xl font-bold text-koba-accent-light">#{receipt.log.log_index}</p>
              </div>
              <div>
                <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Merkle Root</p>
                <p className="font-mono text-sm text-koba-text break-all">{receipt.log.merkle_root}</p>
              </div>
              {receipt.log.previous_receipt_hash && (
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Previous Receipt Hash</p>
                  <p className="font-mono text-sm text-koba-text break-all">{receipt.log.previous_receipt_hash}</p>
                </div>
              )}
            </div>
          </div>

          {/* Cryptographic Signature */}
          <div className="bg-koba-bg-card border border-koba-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-koba-border">
              <h2 className="text-lg font-semibold text-koba-text">Cryptographic Signature</h2>
            </div>
            <div className="p-6 space-y-4">
              {receipt.issuer_public_key && (
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Issuer Public Key</p>
                  <p className="font-mono text-sm text-koba-text break-all">{receipt.issuer_public_key}</p>
                </div>
              )}
              {receipt.signature && (
                <div>
                  <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Signature</p>
                  <p className="font-mono text-sm text-koba-text break-all">{receipt.signature}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </AppShell>
  );
}
