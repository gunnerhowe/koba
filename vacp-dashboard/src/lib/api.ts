export const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export function getAuthHeaders(): HeadersInit {
  const token = typeof window !== 'undefined'
    ? (localStorage.getItem('koba_token') || sessionStorage.getItem('koba_token'))
    : null;
  const headers: HeadersInit = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export interface Receipt {
  receipt_id: string;
  timestamp: string;
  agent_id: string;
  tenant_id: string;
  session_id: string;
  tool: {
    id: string;
    name: string;
    request_hash: string;
    response_hash?: string;
  };
  policy: {
    bundle_id: string;
    policy_hash: string;
    decision: 'allow' | 'deny' | 'pending';
    rules_matched: string[];
  };
  log: {
    log_index: number;
    merkle_root: string;
    previous_receipt_hash?: string;
  };
  signature?: string;
  issuer_public_key?: string;
}

export interface TreeHead {
  tree_size: number;
  root_hash: string;
  timestamp: string;
  signature?: string;
}

export interface Stats {
  total_requests: number;
  allowed: number;
  denied: number;
  pending_approval: number;
}

export interface MerkleProof {
  receipt_hash: string;
  merkle_path: Array<{
    hash: string;
    direction: 'left' | 'right';
  }>;
  root_hash: string;
  tree_size: number;
}

export interface VerifyResult {
  valid: boolean;
  signature_valid: boolean;
  proof_valid: boolean;
  receipt?: Receipt;
}

export interface CatalogTool {
  id: string;
  name: string;
  description?: string;
  categories: string[];
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  requires_approval: boolean;
  schema?: {
    parameters?: Array<{
      name: string;
      type: string;
      required?: boolean;
      default?: string | number | boolean | null;
    }>;
  };
}

export interface Approval {
  id: string;
  tool_id: string;
  agent_id: string;
  tenant_id: string;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  request_hash: string;
  created_at: string;
  expires_at?: string;
  approved_by?: string;
  approved_at?: string;
}

export async function fetchStats(): Promise<Stats> {
  const res = await fetch(`${API_BASE}/stats`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchReceipts(page = 0, limit = 20): Promise<{ entries: Receipt[]; total: number }> {
  const res = await fetch(`${API_BASE}/v1/audit/entries?offset=${page * limit}&limit=${limit}`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch receipts');
  return res.json();
}

export async function fetchReceipt(id: string): Promise<{ receipt: Receipt; proof?: MerkleProof }> {
  const res = await fetch(`${API_BASE}/v1/receipts/${id}/proof`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch receipt');
  return res.json();
}

export async function fetchTreeHead(): Promise<TreeHead> {
  const res = await fetch(`${API_BASE}/v1/audit/tree-head`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch tree head');
  return res.json();
}

export async function verifyReceipt(receiptId: string): Promise<VerifyResult> {
  const res = await fetch(`${API_BASE}/v1/receipts/verify`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ receipt_id: receiptId }),
  });
  if (!res.ok) throw new Error('Failed to verify receipt');
  return res.json();
}

export async function fetchTools(): Promise<CatalogTool[]> {
  const res = await fetch(`${API_BASE}/v1/tools/catalog`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch tools');
  const data = await res.json();
  return data.tools || [];
}

export async function fetchApprovals(): Promise<Approval[]> {
  const res = await fetch(`${API_BASE}/v1/approvals`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch approvals');
  const data = await res.json();
  return data.approvals || [];
}
