'use client';

import Link from 'next/link';
import { Receipt } from '@/lib/api';
import { CheckCircle, XCircle, Clock, ExternalLink, AlertTriangle } from 'lucide-react';

interface ReceiptCardProps {
  receipt: Receipt;
  compact?: boolean;
}

const decisionStyles = {
  allow: {
    bg: 'bg-koba-success/20',
    border: 'border-koba-success/30',
    text: 'text-koba-success',
    icon: CheckCircle,
    label: 'ALLOWED',
  },
  deny: {
    bg: 'bg-koba-danger/20',
    border: 'border-koba-danger/30',
    text: 'text-koba-danger',
    icon: XCircle,
    label: 'DENIED',
  },
  pending: {
    bg: 'bg-koba-warning/20',
    border: 'border-koba-warning/30',
    text: 'text-koba-warning',
    icon: Clock,
    label: 'PENDING',
  },
  allow_with_conditions: {
    bg: 'bg-koba-warning/20',
    border: 'border-koba-warning/30',
    text: 'text-koba-warning',
    icon: AlertTriangle,
    label: 'Conditional',
  },
};

export default function ReceiptCard({ receipt, compact = false }: ReceiptCardProps) {
  const style = decisionStyles[receipt.policy.decision] || decisionStyles.deny;
  const Icon = style.icon;
  const timestamp = new Date(receipt.timestamp).toLocaleString();

  if (compact) {
    return (
      <Link
        href={`/receipts/${receipt.receipt_id}`}
        className="flex items-center justify-between p-4 bg-koba-bg-card border border-koba-border rounded-lg hover:border-koba-accent/30 transition-all group"
      >
        <div className="flex items-center gap-4">
          <div className={`w-10 h-10 rounded-lg ${style.bg} ${style.border} border flex items-center justify-center`}>
            <Icon className={`w-5 h-5 ${style.text}`} />
          </div>
          <div>
            <p className="text-koba-text font-medium">{receipt.tool.name}</p>
            <p className="text-koba-text-secondary text-sm font-mono">
              {receipt.receipt_id.slice(0, 16)}...
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <p className={`text-sm font-medium ${style.text}`}>{style.label}</p>
            <p className="text-koba-text-secondary text-xs">{timestamp}</p>
          </div>
          <ExternalLink className="w-4 h-4 text-koba-text-secondary opacity-0 group-hover:opacity-100 transition-opacity" />
        </div>
      </Link>
    );
  }

  return (
    <div className="bg-koba-bg-card border border-koba-border rounded-xl overflow-hidden">
      {/* Header */}
      <div className={`px-6 py-4 ${style.bg} border-b ${style.border}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Icon className={`w-6 h-6 ${style.text}`} />
            <span className={`font-bold ${style.text}`}>{style.label}</span>
          </div>
          <span className="text-koba-text-secondary text-sm">{timestamp}</span>
        </div>
      </div>

      {/* Body */}
      <div className="p-6 space-y-4">
        <div>
          <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Receipt ID</p>
          <p className="font-mono text-sm text-koba-text break-all">{receipt.receipt_id}</p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Tool</p>
            <p className="text-koba-text">{receipt.tool.name}</p>
          </div>
          <div>
            <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Agent</p>
            <p className="text-koba-text">{receipt.agent_id}</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Tenant</p>
            <p className="text-koba-text">{receipt.tenant_id}</p>
          </div>
          <div>
            <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-1">Log Index</p>
            <p className="text-koba-text">#{receipt.log.log_index}</p>
          </div>
        </div>

        {receipt.policy.rules_matched.length > 0 && (
          <div>
            <p className="text-koba-text-secondary text-xs uppercase tracking-wider mb-2">Rules Matched</p>
            <div className="flex flex-wrap gap-2">
              {receipt.policy.rules_matched.map((rule) => (
                <span
                  key={rule}
                  className="px-2 py-1 bg-koba-bg rounded text-xs text-koba-text-secondary border border-koba-border"
                >
                  {rule}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-6 py-4 border-t border-koba-border bg-koba-bg">
        <Link
          href={`/receipts/${receipt.receipt_id}`}
          className="text-koba-accent-light hover:underline text-sm flex items-center gap-2"
        >
          View Full Details
          <ExternalLink className="w-4 h-4" />
        </Link>
      </div>
    </div>
  );
}
