'use client';

import { useEffect, useState, useMemo } from 'react';
import AppShell from '@/components/AppShell';
import { useAuth } from '@/lib/auth';
import { useRouter } from 'next/navigation';
import { useToast } from '@/hooks/useToast';
import ToastContainer from '@/components/Toast';
import Spinner from '@/components/Spinner';
import { API_BASE } from '@/lib/api';
import {
  Mail, FolderOpen, Calendar, MessageSquare, Users, Globe, Database,
  Cloud, Terminal, FileText, CreditCard, Share2, Bell, Shield, Cpu,
  Search, X, Check, ShieldCheck, ShieldAlert, ShieldX, Clock,
  ChevronDown, Zap, Eye, Lock, Trash2, Plus,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import HelpButton from '@/components/HelpButton';
import { helpContent } from '@/lib/helpContent';

/* ==========================================================================
   TYPES
   ========================================================================== */

type PolicyAction = 'allow' | 'require_approval' | 'deny';

interface CatalogTool {
  id: string;
  name: string;
  description: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  suggested: PolicyAction;
}

interface ToolCategory {
  id: string;
  name: string;
  icon: LucideIcon;
  description: string;
  bgColor: string;
  iconColor: string;
  borderColor: string;
  tools: CatalogTool[];
}

/* ==========================================================================
   TOOL CATALOG — 15 categories, 107 pre-made tools
   ========================================================================== */

const TOOL_CATALOG: ToolCategory[] = [
  {
    id: 'email',
    name: 'Email',
    icon: Mail,
    description: 'Reading, sending, and managing emails',
    bgColor: 'rgba(124,58,237,0.12)',
    iconColor: '#a78bfa',
    borderColor: 'rgba(124,58,237,0.25)',
    tools: [
      { id: 'email.read', name: 'Read Emails', description: 'View and read email messages from your inbox', risk: 'low', suggested: 'allow' },
      { id: 'email.send', name: 'Send Emails', description: 'Compose and send new email messages to anyone', risk: 'high', suggested: 'require_approval' },
      { id: 'email.delete', name: 'Delete Emails', description: 'Permanently delete email messages', risk: 'high', suggested: 'deny' },
      { id: 'email.draft', name: 'Draft Emails', description: 'Create email drafts without sending them', risk: 'medium', suggested: 'allow' },
      { id: 'email.reply', name: 'Reply to Emails', description: 'Send replies to received emails', risk: 'high', suggested: 'require_approval' },
      { id: 'email.forward', name: 'Forward Emails', description: 'Forward emails to other recipients', risk: 'high', suggested: 'require_approval' },
      { id: 'email.search', name: 'Search Emails', description: 'Search through your email messages', risk: 'low', suggested: 'allow' },
      { id: 'email.labels', name: 'Manage Labels', description: 'Create, edit, and apply email labels or folders', risk: 'low', suggested: 'allow' },
    ],
  },
  {
    id: 'files',
    name: 'Files & Folders',
    icon: FolderOpen,
    description: 'Reading, writing, and managing files on your system',
    bgColor: 'rgba(59,130,246,0.12)',
    iconColor: '#60a5fa',
    borderColor: 'rgba(59,130,246,0.25)',
    tools: [
      { id: 'file.read', name: 'Read Files', description: 'Open and read file contents from your computer', risk: 'low', suggested: 'allow' },
      { id: 'file.write', name: 'Write Files', description: 'Create new files or modify existing ones', risk: 'medium', suggested: 'require_approval' },
      { id: 'file.delete', name: 'Delete Files', description: 'Permanently remove files from your system', risk: 'critical', suggested: 'deny' },
      { id: 'file.list', name: 'List Folders', description: 'View directory contents and file listings', risk: 'low', suggested: 'allow' },
      { id: 'file.move', name: 'Move Files', description: 'Move files between folders or drives', risk: 'medium', suggested: 'require_approval' },
      { id: 'file.copy', name: 'Copy Files', description: 'Duplicate files to another location', risk: 'low', suggested: 'allow' },
      { id: 'file.mkdir', name: 'Create Folders', description: 'Create new directories on your system', risk: 'low', suggested: 'allow' },
      { id: 'file.upload', name: 'Upload Files', description: 'Upload files to external services or servers', risk: 'high', suggested: 'require_approval' },
      { id: 'file.download', name: 'Download Files', description: 'Download files from the internet to your system', risk: 'medium', suggested: 'require_approval' },
      { id: 'file.search', name: 'Search Files', description: 'Search for files by name, type, or content', risk: 'low', suggested: 'allow' },
    ],
  },
  {
    id: 'calendar',
    name: 'Calendar',
    icon: Calendar,
    description: 'Viewing and managing calendar events and scheduling',
    bgColor: 'rgba(20,184,166,0.12)',
    iconColor: '#2dd4bf',
    borderColor: 'rgba(20,184,166,0.25)',
    tools: [
      { id: 'calendar.read', name: 'View Calendar', description: 'See your calendar events and schedules', risk: 'low', suggested: 'allow' },
      { id: 'calendar.create', name: 'Create Events', description: 'Add new events to your calendar', risk: 'medium', suggested: 'require_approval' },
      { id: 'calendar.update', name: 'Update Events', description: 'Change details of existing calendar events', risk: 'medium', suggested: 'require_approval' },
      { id: 'calendar.delete', name: 'Delete Events', description: 'Remove events from your calendar', risk: 'high', suggested: 'deny' },
      { id: 'calendar.invite', name: 'Send Invites', description: 'Send meeting invitations to other people', risk: 'high', suggested: 'require_approval' },
      { id: 'calendar.availability', name: 'Check Availability', description: 'View free/busy times on your calendar', risk: 'low', suggested: 'allow' },
    ],
  },
  {
    id: 'messages',
    name: 'Messages & Chat',
    icon: MessageSquare,
    description: 'Sending and reading messages across chat platforms',
    bgColor: 'rgba(34,197,94,0.12)',
    iconColor: '#4ade80',
    borderColor: 'rgba(34,197,94,0.25)',
    tools: [
      { id: 'chat.send', name: 'Send Messages', description: 'Send chat messages to individuals or groups', risk: 'high', suggested: 'require_approval' },
      { id: 'chat.read', name: 'Read Messages', description: 'View received chat messages and history', risk: 'low', suggested: 'allow' },
      { id: 'slack.send', name: 'Send Slack Messages', description: 'Post messages to Slack channels or DMs', risk: 'high', suggested: 'require_approval' },
      { id: 'slack.read', name: 'Read Slack', description: 'Read Slack channel messages and threads', risk: 'low', suggested: 'allow' },
      { id: 'teams.send', name: 'Send Teams Messages', description: 'Post messages in Microsoft Teams', risk: 'high', suggested: 'require_approval' },
      { id: 'discord.post', name: 'Post to Discord', description: 'Send messages to Discord channels', risk: 'high', suggested: 'require_approval' },
      { id: 'telegram.send', name: 'Send Telegram', description: 'Send messages via Telegram', risk: 'high', suggested: 'require_approval' },
      { id: 'sms.send', name: 'Send SMS', description: 'Send text messages to phone numbers', risk: 'high', suggested: 'require_approval' },
    ],
  },
  {
    id: 'contacts',
    name: 'Contacts & People',
    icon: Users,
    description: 'Managing your address book and contact information',
    bgColor: 'rgba(99,102,241,0.12)',
    iconColor: '#818cf8',
    borderColor: 'rgba(99,102,241,0.25)',
    tools: [
      { id: 'contacts.read', name: 'Read Contacts', description: 'View names, emails, and phone numbers in your contacts', risk: 'medium', suggested: 'allow' },
      { id: 'contacts.add', name: 'Add Contacts', description: 'Add new people to your contact list', risk: 'medium', suggested: 'require_approval' },
      { id: 'contacts.update', name: 'Update Contacts', description: 'Edit existing contact information', risk: 'medium', suggested: 'require_approval' },
      { id: 'contacts.delete', name: 'Delete Contacts', description: 'Remove people from your contact list', risk: 'high', suggested: 'deny' },
      { id: 'contacts.export', name: 'Export Contacts', description: 'Export your contact list to a file', risk: 'high', suggested: 'require_approval' },
    ],
  },
  {
    id: 'web',
    name: 'Web & Browsing',
    icon: Globe,
    description: 'Browsing websites, searching the web, and downloading',
    bgColor: 'rgba(6,182,212,0.12)',
    iconColor: '#22d3ee',
    borderColor: 'rgba(6,182,212,0.25)',
    tools: [
      { id: 'web.browse', name: 'Browse Websites', description: 'Visit and view web pages', risk: 'low', suggested: 'allow' },
      { id: 'web.search', name: 'Web Search', description: 'Search the internet using search engines', risk: 'low', suggested: 'allow' },
      { id: 'web.form_fill', name: 'Fill Out Forms', description: 'Enter data into web forms on your behalf', risk: 'high', suggested: 'require_approval' },
      { id: 'web.submit', name: 'Submit Forms', description: 'Submit web forms (sign-ups, purchases, etc.)', risk: 'critical', suggested: 'deny' },
      { id: 'web.download', name: 'Download from Web', description: 'Download files from websites', risk: 'medium', suggested: 'require_approval' },
      { id: 'web.screenshot', name: 'Take Screenshots', description: 'Capture screenshots of web pages', risk: 'low', suggested: 'allow' },
      { id: 'web.api', name: 'Call External APIs', description: 'Make HTTP requests to external web services', risk: 'medium', suggested: 'require_approval' },
    ],
  },
  {
    id: 'database',
    name: 'Database',
    icon: Database,
    description: 'Querying, modifying, and managing database records',
    bgColor: 'rgba(249,115,22,0.12)',
    iconColor: '#fb923c',
    borderColor: 'rgba(249,115,22,0.25)',
    tools: [
      { id: 'db.query', name: 'Query Database', description: 'Run read-only queries to view data', risk: 'low', suggested: 'allow' },
      { id: 'db.insert', name: 'Insert Records', description: 'Add new records to the database', risk: 'medium', suggested: 'require_approval' },
      { id: 'db.update', name: 'Update Records', description: 'Modify existing records in the database', risk: 'high', suggested: 'require_approval' },
      { id: 'db.delete', name: 'Delete Records', description: 'Remove records from the database', risk: 'critical', suggested: 'deny' },
      { id: 'db.sql', name: 'Run Raw SQL', description: 'Execute raw SQL statements directly', risk: 'critical', suggested: 'deny' },
      { id: 'db.export', name: 'Export Data', description: 'Export database tables or query results', risk: 'high', suggested: 'require_approval' },
      { id: 'db.import', name: 'Import Data', description: 'Import data into the database from files', risk: 'high', suggested: 'require_approval' },
      { id: 'db.backup', name: 'Backup Database', description: 'Create database backups', risk: 'medium', suggested: 'allow' },
    ],
  },
  {
    id: 'cloud',
    name: 'Cloud Storage',
    icon: Cloud,
    description: 'Managing files in cloud services like S3, Google Drive, etc.',
    bgColor: 'rgba(14,165,233,0.12)',
    iconColor: '#38bdf8',
    borderColor: 'rgba(14,165,233,0.25)',
    tools: [
      { id: 'cloud.read', name: 'Read Cloud Files', description: 'Download or view files from cloud storage (S3, GCS, Azure)', risk: 'low', suggested: 'allow' },
      { id: 'cloud.upload', name: 'Upload to Cloud', description: 'Upload files to cloud storage services', risk: 'medium', suggested: 'require_approval' },
      { id: 'cloud.delete', name: 'Delete Cloud Files', description: 'Remove files from cloud storage', risk: 'critical', suggested: 'deny' },
      { id: 'cloud.list', name: 'List Cloud Files', description: 'View file listings in cloud buckets or drives', risk: 'low', suggested: 'allow' },
      { id: 'cloud.sync', name: 'Sync Cloud Folders', description: 'Synchronize local folders with cloud storage', risk: 'high', suggested: 'require_approval' },
      { id: 'gdrive.read', name: 'Read Google Drive', description: 'Access files stored in Google Drive', risk: 'low', suggested: 'allow' },
      { id: 'gdrive.upload', name: 'Upload to Google Drive', description: 'Save files to your Google Drive', risk: 'medium', suggested: 'require_approval' },
    ],
  },
  {
    id: 'code',
    name: 'Code & Terminal',
    icon: Terminal,
    description: 'Running code, scripts, shell commands, and managing processes',
    bgColor: 'rgba(239,68,68,0.12)',
    iconColor: '#f87171',
    borderColor: 'rgba(239,68,68,0.25)',
    tools: [
      { id: 'code.execute', name: 'Execute Code', description: 'Run code snippets in Python, JavaScript, etc.', risk: 'critical', suggested: 'require_approval' },
      { id: 'shell.run', name: 'Shell Commands', description: 'Execute terminal/command-line commands', risk: 'critical', suggested: 'require_approval' },
      { id: 'code.install', name: 'Install Packages', description: 'Install software packages (npm, pip, etc.)', risk: 'high', suggested: 'require_approval' },
      { id: 'code.script', name: 'Run Scripts', description: 'Execute script files (.sh, .bat, .py)', risk: 'critical', suggested: 'deny' },
      { id: 'git.commit', name: 'Git Commit', description: 'Create git commits with your changes', risk: 'medium', suggested: 'require_approval' },
      { id: 'git.push', name: 'Git Push', description: 'Push commits to a remote repository', risk: 'high', suggested: 'require_approval' },
      { id: 'process.start', name: 'Start Processes', description: 'Launch new system processes or applications', risk: 'critical', suggested: 'deny' },
      { id: 'process.kill', name: 'Stop Processes', description: 'Terminate running system processes', risk: 'critical', suggested: 'deny' },
    ],
  },
  {
    id: 'documents',
    name: 'Documents & Office',
    icon: FileText,
    description: 'Creating, editing, and converting documents and spreadsheets',
    bgColor: 'rgba(16,185,129,0.12)',
    iconColor: '#34d399',
    borderColor: 'rgba(16,185,129,0.25)',
    tools: [
      { id: 'doc.read', name: 'Read Documents', description: 'Open and read Word, PDF, and text documents', risk: 'low', suggested: 'allow' },
      { id: 'doc.create', name: 'Create Documents', description: 'Create new documents from scratch', risk: 'medium', suggested: 'allow' },
      { id: 'doc.edit', name: 'Edit Documents', description: 'Make changes to existing documents', risk: 'medium', suggested: 'require_approval' },
      { id: 'doc.convert', name: 'Convert Documents', description: 'Convert files between formats (PDF, DOCX, etc.)', risk: 'low', suggested: 'allow' },
      { id: 'doc.pdf', name: 'Generate PDFs', description: 'Create PDF files from data or templates', risk: 'low', suggested: 'allow' },
      { id: 'sheet.read', name: 'Read Spreadsheets', description: 'View data in Excel or Google Sheets', risk: 'low', suggested: 'allow' },
      { id: 'sheet.edit', name: 'Edit Spreadsheets', description: 'Modify cells and formulas in spreadsheets', risk: 'medium', suggested: 'require_approval' },
    ],
  },
  {
    id: 'payments',
    name: 'Payments & Finance',
    icon: CreditCard,
    description: 'Processing payments, viewing transactions, and financial operations',
    bgColor: 'rgba(234,179,8,0.12)',
    iconColor: '#fbbf24',
    borderColor: 'rgba(234,179,8,0.25)',
    tools: [
      { id: 'pay.process', name: 'Process Payments', description: 'Initiate payment transactions', risk: 'critical', suggested: 'deny' },
      { id: 'pay.balance', name: 'Check Balance', description: 'View account balances and summaries', risk: 'medium', suggested: 'require_approval' },
      { id: 'pay.transfer', name: 'Transfer Funds', description: 'Move money between accounts', risk: 'critical', suggested: 'deny' },
      { id: 'pay.transactions', name: 'View Transactions', description: 'See payment history and transaction logs', risk: 'medium', suggested: 'allow' },
      { id: 'pay.invoice', name: 'Create Invoices', description: 'Generate and send invoices', risk: 'high', suggested: 'require_approval' },
      { id: 'pay.subscribe', name: 'Manage Subscriptions', description: 'Create, modify, or cancel subscriptions', risk: 'critical', suggested: 'deny' },
      { id: 'pay.refund', name: 'Issue Refunds', description: 'Process refunds for past transactions', risk: 'critical', suggested: 'deny' },
    ],
  },
  {
    id: 'social',
    name: 'Social Media',
    icon: Share2,
    description: 'Posting, reading, and interacting on social media platforms',
    bgColor: 'rgba(236,72,153,0.12)',
    iconColor: '#f472b6',
    borderColor: 'rgba(236,72,153,0.25)',
    tools: [
      { id: 'social.read', name: 'Read Posts', description: 'View posts and feeds on social platforms', risk: 'low', suggested: 'allow' },
      { id: 'social.post', name: 'Create Posts', description: 'Publish new posts to social media', risk: 'high', suggested: 'require_approval' },
      { id: 'social.reply', name: 'Reply to Posts', description: 'Comment on or reply to social media posts', risk: 'high', suggested: 'require_approval' },
      { id: 'social.upload', name: 'Upload Media', description: 'Upload photos or videos to social platforms', risk: 'high', suggested: 'require_approval' },
      { id: 'social.like', name: 'Like & React', description: 'Like, upvote, or react to posts', risk: 'low', suggested: 'allow' },
      { id: 'social.follow', name: 'Follow & Unfollow', description: 'Follow or unfollow accounts', risk: 'medium', suggested: 'require_approval' },
      { id: 'social.dm', name: 'Send Direct Messages', description: 'Send private messages on social platforms', risk: 'high', suggested: 'require_approval' },
    ],
  },
  {
    id: 'notifications',
    name: 'Notifications',
    icon: Bell,
    description: 'Sending alerts, push notifications, and reminders',
    bgColor: 'rgba(245,158,11,0.12)',
    iconColor: '#fbbf24',
    borderColor: 'rgba(245,158,11,0.25)',
    tools: [
      { id: 'notify.push', name: 'Push Notifications', description: 'Send push notifications to devices', risk: 'medium', suggested: 'require_approval' },
      { id: 'notify.alert', name: 'System Alerts', description: 'Display system alerts and warnings', risk: 'low', suggested: 'allow' },
      { id: 'notify.reminder', name: 'Set Reminders', description: 'Create timed reminders and follow-ups', risk: 'low', suggested: 'allow' },
      { id: 'notify.schedule', name: 'Schedule Notifications', description: 'Queue notifications for future delivery', risk: 'medium', suggested: 'allow' },
      { id: 'notify.webhook', name: 'Fire Webhooks', description: 'Trigger webhook callbacks to external services', risk: 'high', suggested: 'require_approval' },
    ],
  },
  {
    id: 'security',
    name: 'Security & Admin',
    icon: Shield,
    description: 'Managing users, permissions, secrets, and system administration',
    bgColor: 'rgba(239,68,68,0.12)',
    iconColor: '#f87171',
    borderColor: 'rgba(239,68,68,0.25)',
    tools: [
      { id: 'admin.users', name: 'Manage Users', description: 'Create, edit, or delete user accounts', risk: 'critical', suggested: 'deny' },
      { id: 'admin.permissions', name: 'Change Permissions', description: 'Modify user roles and access permissions', risk: 'critical', suggested: 'deny' },
      { id: 'admin.secrets', name: 'Access Secrets', description: 'Read API keys, passwords, and credentials', risk: 'critical', suggested: 'deny' },
      { id: 'admin.apikeys', name: 'Manage API Keys', description: 'Create, rotate, or revoke API keys', risk: 'critical', suggested: 'deny' },
      { id: 'admin.audit', name: 'View Audit Logs', description: 'Read system audit and activity logs', risk: 'medium', suggested: 'allow' },
      { id: 'admin.passwords', name: 'Manage Passwords', description: 'Reset or change user passwords', risk: 'critical', suggested: 'deny' },
      { id: 'admin.config', name: 'System Configuration', description: 'Modify system settings and configurations', risk: 'critical', suggested: 'deny' },
    ],
  },
  {
    id: 'system',
    name: 'System & Hardware',
    icon: Cpu,
    description: 'Accessing system info, clipboard, screenshots, and hardware',
    bgColor: 'rgba(100,116,139,0.12)',
    iconColor: '#94a3b8',
    borderColor: 'rgba(100,116,139,0.25)',
    tools: [
      { id: 'system.clipboard_read', name: 'Read Clipboard', description: 'Read text or images copied to your clipboard', risk: 'medium', suggested: 'allow' },
      { id: 'system.clipboard_write', name: 'Write to Clipboard', description: 'Copy text or data to your clipboard', risk: 'low', suggested: 'allow' },
      { id: 'system.screenshot', name: 'Take Screenshots', description: 'Capture screenshots of your screen', risk: 'medium', suggested: 'require_approval' },
      { id: 'system.info', name: 'System Information', description: 'Read device name, OS version, hardware details', risk: 'low', suggested: 'allow' },
      { id: 'system.env', name: 'Environment Variables', description: 'Read system environment variables', risk: 'high', suggested: 'deny' },
      { id: 'system.processes', name: 'View Processes', description: 'List running processes and applications', risk: 'medium', suggested: 'allow' },
      { id: 'system.network', name: 'Network Information', description: 'View network connections and interfaces', risk: 'medium', suggested: 'allow' },
    ],
  },
];

/* ==========================================================================
   ACTION BUTTON STYLES (static classes to avoid Tailwind purging)
   ========================================================================== */

const ACTION_STYLES = {
  allow: {
    active: 'bg-emerald-500/20 border-emerald-500 text-emerald-400',
    inactive: 'border-transparent text-zinc-500 hover:text-emerald-400 hover:border-emerald-500/40 hover:bg-emerald-500/10',
    icon: ShieldCheck,
    label: 'Allow',
  },
  require_approval: {
    active: 'bg-amber-500/20 border-amber-500 text-amber-400',
    inactive: 'border-transparent text-zinc-500 hover:text-amber-400 hover:border-amber-500/40 hover:bg-amber-500/10',
    icon: Clock,
    label: 'Approval',
  },
  deny: {
    active: 'bg-red-500/20 border-red-500 text-red-400',
    inactive: 'border-transparent text-zinc-500 hover:text-red-400 hover:border-red-500/40 hover:bg-red-500/10',
    icon: ShieldX,
    label: 'Block',
  },
} as const;

const RISK_STYLES = {
  low: { dot: '#4ade80', label: 'Low Risk' },
  medium: { dot: '#fbbf24', label: 'Medium' },
  high: { dot: '#fb923c', label: 'High Risk' },
  critical: { dot: '#f87171', label: 'Critical' },
};

/* ==========================================================================
   STORAGE HELPERS — persist tool policies in localStorage
   ========================================================================== */

const STORAGE_KEY = 'koba_tool_policies';

function loadSavedPolicies(): Record<string, PolicyAction> {
  if (typeof window === 'undefined') return {};
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved ? JSON.parse(saved) : {};
  } catch {
    return {};
  }
}

function savePolicies(policies: Record<string, PolicyAction>) {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(policies));
  } catch { /* ignore */ }
}

/* ==========================================================================
   MAIN PAGE COMPONENT
   ========================================================================== */

export default function ToolsPage() {
  const router = useRouter();
  const { user, token, loading: authLoading } = useAuth();
  const { toasts, showToast, dismissToast } = useToast();

  const [searchQuery, setSearchQuery] = useState('');
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null);
  const [toolPolicies, setToolPolicies] = useState<Record<string, PolicyAction>>({});
  const [savingTool, setSavingTool] = useState<string | null>(null);
  const [initialized, setInitialized] = useState(false);
  const [protectionLevel, setProtectionLevel] = useState<string | null>(null);
  const [applyingPreset, setApplyingPreset] = useState(false);

  // Load policies: try backend first, fall back to localStorage, then defaults
  useEffect(() => {
    async function loadPolicies() {
      // Try backend first
      if (token) {
        try {
          const res = await fetch(`${API_BASE}/v1/tools/policies`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (res.ok) {
            const data = await res.json();
            if (data.policies && Object.keys(data.policies).length > 0) {
              setToolPolicies(data.policies);
              savePolicies(data.policies);
              setProtectionLevel(data.protection_level || null);
              setInitialized(true);
              return;
            }
          }
        } catch { /* fall through to localStorage */ }
      }
      // Fallback to localStorage
      const saved = loadSavedPolicies();
      if (Object.keys(saved).length === 0) {
        const defaults: Record<string, PolicyAction> = {};
        TOOL_CATALOG.forEach(cat => {
          cat.tools.forEach(tool => {
            defaults[tool.id] = tool.suggested;
          });
        });
        setToolPolicies(defaults);
        savePolicies(defaults);
      } else {
        setToolPolicies(saved);
      }
      setInitialized(true);
    }
    loadPolicies();
  }, [token]);

  // Auth redirect
  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login');
    }
  }, [user, authLoading, router]);

  // Filter catalog by search
  const filteredCatalog = useMemo(() => {
    if (!searchQuery.trim()) return TOOL_CATALOG;
    const q = searchQuery.toLowerCase();
    return TOOL_CATALOG
      .map(cat => ({
        ...cat,
        tools: cat.tools.filter(
          t => t.name.toLowerCase().includes(q) ||
               t.description.toLowerCase().includes(q) ||
               cat.name.toLowerCase().includes(q)
        ),
      }))
      .filter(cat => cat.tools.length > 0);
  }, [searchQuery]);

  // Summary stats
  const stats = useMemo(() => {
    let allowed = 0, approval = 0, blocked = 0;
    Object.values(toolPolicies).forEach(p => {
      if (p === 'allow') allowed++;
      else if (p === 'require_approval') approval++;
      else if (p === 'deny') blocked++;
    });
    return { allowed, approval, blocked, total: allowed + approval + blocked };
  }, [toolPolicies]);

  // Category stats
  const categoryStats = useMemo(() => {
    const result: Record<string, { allowed: number; approval: number; blocked: number }> = {};
    TOOL_CATALOG.forEach(cat => {
      let allowed = 0, approval = 0, blocked = 0;
      cat.tools.forEach(t => {
        const p = toolPolicies[t.id];
        if (p === 'allow') allowed++;
        else if (p === 'require_approval') approval++;
        else if (p === 'deny') blocked++;
      });
      result[cat.id] = { allowed, approval, blocked };
    });
    return result;
  }, [toolPolicies]);

  // Handle setting a policy on a tool
  const handleSetPolicy = async (tool: CatalogTool, action: PolicyAction) => {
    const previousPolicies = { ...toolPolicies };

    // Optimistic update
    const newPolicies = { ...toolPolicies, [tool.id]: action };
    setToolPolicies(newPolicies);
    savePolicies(newPolicies);

    setSavingTool(tool.id);
    try {
      if (token) {
        const res = await fetch(`${API_BASE}/v1/tools/policy`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            tool_id: tool.id,
            decision: action,
            name: tool.name,
          }),
        });
        if (!res.ok) {
          // Revert on failure
          setToolPolicies(previousPolicies);
          savePolicies(previousPolicies);
          showToast(`Failed to save policy for ${tool.name}`, 'error');
          return;
        }
      }
    } catch {
      // Network error — keep optimistic update since localStorage has it
    } finally {
      setSavingTool(null);
    }

    if (action === 'deny') {
      showToast(`${tool.name}: Blocked`, 'warning');
    } else if (action === 'require_approval') {
      showToast(`${tool.name}: Requires Approval`, 'info');
    } else {
      showToast(`${tool.name}: Allowed`, 'success');
    }
  };

  // Bulk actions for a category
  const handleBulkAction = async (catId: string, action: PolicyAction) => {
    const cat = TOOL_CATALOG.find(c => c.id === catId);
    if (!cat) return;

    // Optimistic update
    const newPolicies = { ...toolPolicies };
    const bulkPayload: Record<string, string> = {};
    cat.tools.forEach(t => {
      newPolicies[t.id] = action;
      bulkPayload[t.id] = action;
    });
    setToolPolicies(newPolicies);
    savePolicies(newPolicies);

    // Sync to backend
    if (token) {
      try {
        await fetch(`${API_BASE}/v1/tools/policies/bulk`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ policies: bulkPayload }),
        });
      } catch { /* localStorage has it */ }
    }

    const label = action === 'allow' ? 'allowed' : action === 'deny' ? 'blocked' : 'set to require approval';
    showToast(`All ${cat.name} tools ${label}`, action === 'deny' ? 'warning' : 'success');
  };

  // Apply a protection preset
  const handlePreset = async (level: 'basic' | 'standard' | 'maximum') => {
    if (!token) return;
    setApplyingPreset(true);
    try {
      const res = await fetch(`${API_BASE}/v1/setup/protection-level`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ level }),
      });
      if (res.ok) {
        setProtectionLevel(level);
        // Reload policies from backend to reflect new base rules
        try {
          const policiesRes = await fetch(`${API_BASE}/v1/tools/policies`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (policiesRes.ok) {
            const data = await policiesRes.json();
            if (data.policies) {
              setToolPolicies(data.policies);
              savePolicies(data.policies);
            }
          }
        } catch { /* ignore */ }
        const labels = { basic: 'Log Only', standard: 'Recommended', maximum: 'Maximum Protection' };
        showToast(`Protection set to: ${labels[level]}`, 'success');
      } else {
        showToast('Failed to set protection level', 'error');
      }
    } catch {
      showToast('Failed to connect to backend', 'error');
    } finally {
      setApplyingPreset(false);
    }
  };

  // Auth guard
  if (authLoading || !user) {
    return (
      <div className="min-h-screen bg-koba-bg flex items-center justify-center">
        <Spinner size="lg" />
      </div>
    );
  }

  if (!initialized) {
    return (
      <AppShell>
        <div className="flex items-center justify-center h-64">
          <Spinner size="lg" />
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      <div className="max-w-7xl mx-auto">
        {/* ═══════════ HEADER ═══════════ */}
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl sm:text-3xl font-bold text-koba-text">
              What Can Your AI Do?
            </h1>
            <HelpButton content={helpContent.tools} />
          </div>
          <p className="text-koba-text-secondary mt-1">
            Control exactly what your AI agents are allowed to access. Click a category to manage its tools.
          </p>
        </div>

        {/* ═══════════ SUMMARY BAR ═══════════ */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="bg-koba-bg-card border border-koba-border rounded-xl p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'rgba(34,197,94,0.15)' }}>
              <ShieldCheck className="w-5 h-5" style={{ color: '#4ade80' }} />
            </div>
            <div>
              <p className="text-2xl font-bold text-koba-text">{stats.allowed}</p>
              <p className="text-xs text-koba-text-secondary">Allowed</p>
            </div>
          </div>
          <div className="bg-koba-bg-card border border-koba-border rounded-xl p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'rgba(245,158,11,0.15)' }}>
              <Clock className="w-5 h-5" style={{ color: '#fbbf24' }} />
            </div>
            <div>
              <p className="text-2xl font-bold text-koba-text">{stats.approval}</p>
              <p className="text-xs text-koba-text-secondary">Need Approval</p>
            </div>
          </div>
          <div className="bg-koba-bg-card border border-koba-border rounded-xl p-4 flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: 'rgba(239,68,68,0.15)' }}>
              <ShieldX className="w-5 h-5" style={{ color: '#f87171' }} />
            </div>
            <div>
              <p className="text-2xl font-bold text-koba-text">{stats.blocked}</p>
              <p className="text-xs text-koba-text-secondary">Blocked</p>
            </div>
          </div>
        </div>

        {/* ═══════════ PROTECTION PRESETS ═══════════ */}
        <div className="mb-8">
          <h2 className="text-koba-text font-semibold mb-2">Quick Setup</h2>
          <p className="text-koba-text-secondary text-sm mb-4">
            Choose a protection level, then customize individual tools below if needed.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <button
              onClick={() => handlePreset('basic')}
              disabled={applyingPreset}
              className={`p-5 rounded-xl border-2 text-left transition-all ${
                protectionLevel === 'basic'
                  ? 'border-emerald-500 bg-emerald-500/10'
                  : 'border-koba-border hover:border-emerald-500/40'
              } ${applyingPreset ? 'opacity-50 cursor-wait' : ''}`}
            >
              <Eye className="w-8 h-8 text-emerald-400 mb-3" />
              <h3 className="text-koba-text font-semibold">Log Only</h3>
              <p className="text-koba-text-secondary text-xs mt-1">
                AI can do everything. All actions are recorded so you can review them later. Good for getting started.
              </p>
            </button>
            <button
              onClick={() => handlePreset('standard')}
              disabled={applyingPreset}
              className={`p-5 rounded-xl border-2 text-left transition-all ${
                protectionLevel === 'standard'
                  ? 'border-amber-500 bg-amber-500/10'
                  : 'border-koba-border hover:border-amber-500/40'
              } ${applyingPreset ? 'opacity-50 cursor-wait' : ''}`}
            >
              <Shield className="w-8 h-8 text-amber-400 mb-3" />
              <h3 className="text-koba-text font-semibold">Recommended</h3>
              <p className="text-koba-text-secondary text-xs mt-1">
                AI can read freely. Risky actions like sending emails or deleting files need your approval first.
              </p>
            </button>
            <button
              onClick={() => handlePreset('maximum')}
              disabled={applyingPreset}
              className={`p-5 rounded-xl border-2 text-left transition-all ${
                protectionLevel === 'maximum'
                  ? 'border-red-500 bg-red-500/10'
                  : 'border-koba-border hover:border-red-500/40'
              } ${applyingPreset ? 'opacity-50 cursor-wait' : ''}`}
            >
              <Lock className="w-8 h-8 text-red-400 mb-3" />
              <h3 className="text-koba-text font-semibold">Maximum Protection</h3>
              <p className="text-koba-text-secondary text-xs mt-1">
                Every single action needs your approval. Nothing happens without you saying yes.
              </p>
            </button>
          </div>
        </div>

        {/* ═══════════ SEARCH ═══════════ */}
        <div className="relative mb-8">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-koba-text-muted" />
          <input
            type="text"
            placeholder="Search tools... (e.g. email, delete, payment)"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-12 pr-10 py-3 bg-koba-bg-card border border-koba-border rounded-xl text-koba-text placeholder-koba-text-muted focus:outline-none focus:border-koba-accent focus:ring-1 focus:ring-koba-accent/50 transition-colors"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 p-1 hover:bg-koba-bg-elevated rounded-lg transition-colors"
            >
              <X className="w-4 h-4 text-koba-text-muted" />
            </button>
          )}
        </div>

        {/* ═══════════ CATEGORY GRID ═══════════ */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
          {filteredCatalog.map(cat => {
            const isExpanded = expandedCategory === cat.id;
            const cStats = categoryStats[cat.id] || { allowed: 0, approval: 0, blocked: 0 };
            const Icon = cat.icon;

            return (
              <button
                key={cat.id}
                onClick={() => setExpandedCategory(isExpanded ? null : cat.id)}
                className={`relative bg-koba-bg-card border rounded-xl p-4 text-left transition-all duration-200 hover:scale-[1.02] ${
                  isExpanded
                    ? 'border-koba-accent shadow-glow-sm ring-1 ring-koba-accent/30'
                    : 'border-koba-border hover:border-koba-border-light'
                }`}
              >
                <div
                  className="w-12 h-12 rounded-xl flex items-center justify-center mb-3 border"
                  style={{
                    backgroundColor: cat.bgColor,
                    borderColor: cat.borderColor,
                  }}
                >
                  <Icon className="w-6 h-6" style={{ color: cat.iconColor }} />
                </div>
                <h3 className="text-koba-text font-semibold text-sm">{cat.name}</h3>
                <p className="text-koba-text-muted text-xs mt-0.5">{cat.tools.length} tools</p>

                {/* Mini status bar */}
                <div className="flex gap-1 mt-3">
                  {cStats.allowed > 0 && (
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: 'rgba(34,197,94,0.15)', color: '#4ade80' }}>
                      {cStats.allowed}
                    </span>
                  )}
                  {cStats.approval > 0 && (
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: 'rgba(245,158,11,0.15)', color: '#fbbf24' }}>
                      {cStats.approval}
                    </span>
                  )}
                  {cStats.blocked > 0 && (
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium" style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#f87171' }}>
                      {cStats.blocked}
                    </span>
                  )}
                </div>

                {isExpanded && (
                  <div className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 w-3 h-3 rotate-45 bg-koba-bg-card border-b border-r border-koba-accent" />
                )}
              </button>
            );
          })}
        </div>

        {/* ═══════════ EXPANDED CATEGORY PANEL ═══════════ */}
        {expandedCategory && (() => {
          const cat = filteredCatalog.find(c => c.id === expandedCategory);
          if (!cat) return null;
          const Icon = cat.icon;

          return (
            <div className="bg-koba-bg-card border border-koba-accent/30 rounded-2xl mb-8 overflow-hidden animate-fade-in">
              {/* Category header */}
              <div className="p-6 border-b border-koba-border">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div
                      className="w-12 h-12 rounded-xl flex items-center justify-center border"
                      style={{ backgroundColor: cat.bgColor, borderColor: cat.borderColor }}
                    >
                      <Icon className="w-6 h-6" style={{ color: cat.iconColor }} />
                    </div>
                    <div>
                      <h2 className="text-xl font-bold text-koba-text">{cat.name}</h2>
                      <p className="text-koba-text-secondary text-sm">{cat.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Bulk actions */}
                    <div className="hidden sm:flex items-center gap-1.5 mr-2">
                      <span className="text-koba-text-muted text-xs mr-1">Set all:</span>
                      <button
                        onClick={() => handleBulkAction(cat.id, 'allow')}
                        className="px-2.5 py-1 rounded-lg text-xs font-medium transition-all border border-transparent hover:border-emerald-500/40 hover:bg-emerald-500/10 text-zinc-400 hover:text-emerald-400"
                      >
                        Allow
                      </button>
                      <button
                        onClick={() => handleBulkAction(cat.id, 'require_approval')}
                        className="px-2.5 py-1 rounded-lg text-xs font-medium transition-all border border-transparent hover:border-amber-500/40 hover:bg-amber-500/10 text-zinc-400 hover:text-amber-400"
                      >
                        Approval
                      </button>
                      <button
                        onClick={() => handleBulkAction(cat.id, 'deny')}
                        className="px-2.5 py-1 rounded-lg text-xs font-medium transition-all border border-transparent hover:border-red-500/40 hover:bg-red-500/10 text-zinc-400 hover:text-red-400"
                      >
                        Block
                      </button>
                    </div>

                    <button
                      onClick={() => setExpandedCategory(null)}
                      className="p-2 hover:bg-koba-bg-elevated rounded-lg transition-colors"
                    >
                      <X className="w-5 h-5 text-koba-text-secondary" />
                    </button>
                  </div>
                </div>
              </div>

              {/* Tool list */}
              <div className="divide-y divide-koba-border/50">
                {cat.tools.map(tool => {
                  const currentPolicy = toolPolicies[tool.id] || tool.suggested;
                  const isSaving = savingTool === tool.id;
                  const riskStyle = RISK_STYLES[tool.risk];

                  return (
                    <div
                      key={tool.id}
                      className="flex items-center justify-between px-6 py-4 hover:bg-koba-bg-elevated/30 transition-colors"
                    >
                      {/* Tool info */}
                      <div className="flex-1 min-w-0 mr-6">
                        <div className="flex items-center gap-2.5">
                          <h3 className="text-koba-text font-medium text-sm">{tool.name}</h3>
                          <span className="flex items-center gap-1 text-[10px] font-medium text-koba-text-muted">
                            <span
                              className="w-1.5 h-1.5 rounded-full"
                              style={{ backgroundColor: riskStyle.dot }}
                            />
                            {riskStyle.label}
                          </span>
                        </div>
                        <p className="text-koba-text-secondary text-xs mt-0.5">{tool.description}</p>
                      </div>

                      {/* Action buttons */}
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        {isSaving && <Spinner size="sm" />}
                        {(['allow', 'require_approval', 'deny'] as PolicyAction[]).map(action => {
                          const style = ACTION_STYLES[action];
                          const isActive = currentPolicy === action;
                          const ActionIcon = style.icon;

                          return (
                            <button
                              key={action}
                              onClick={() => handleSetPolicy(tool, action)}
                              disabled={isSaving}
                              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150 border ${
                                isActive ? style.active : style.inactive
                              } ${isSaving ? 'opacity-50' : ''}`}
                            >
                              <ActionIcon className="w-3.5 h-3.5" />
                              <span className="hidden sm:inline">{style.label}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })()}

        {/* ═══════════ NO RESULTS ═══════════ */}
        {searchQuery && filteredCatalog.length === 0 && (
          <div className="bg-koba-bg-card border border-koba-border rounded-xl p-12 text-center">
            <Search className="w-12 h-12 mx-auto mb-4 text-koba-text-secondary opacity-40" />
            <p className="text-koba-text-secondary font-medium">No tools matching &ldquo;{searchQuery}&rdquo;</p>
            <p className="text-koba-text-muted text-sm mt-1">Try searching for &ldquo;email&rdquo;, &ldquo;files&rdquo;, or &ldquo;payment&rdquo;</p>
          </div>
        )}

        {/* ═══════════ HOW IT WORKS ═══════════ */}
        <div className="mt-8 bg-koba-bg-card border border-koba-border rounded-xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <ShieldAlert className="w-5 h-5 text-koba-accent" />
            <h3 className="text-koba-text font-semibold">How This Works</h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
            <div className="flex gap-3">
              <div
                className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold"
                style={{ backgroundColor: 'rgba(34,197,94,0.15)', color: '#4ade80' }}
              >1</div>
              <div>
                <p className="text-koba-text text-sm font-medium">Allow</p>
                <p className="text-koba-text-muted text-xs mt-0.5">
                  The AI can use this tool freely. Good for read-only and low-risk actions.
                </p>
              </div>
            </div>
            <div className="flex gap-3">
              <div
                className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold"
                style={{ backgroundColor: 'rgba(245,158,11,0.15)', color: '#fbbf24' }}
              >2</div>
              <div>
                <p className="text-koba-text text-sm font-medium">Require Approval</p>
                <p className="text-koba-text-muted text-xs mt-0.5">
                  You&apos;ll be asked to approve each time the AI tries to use this tool.
                </p>
              </div>
            </div>
            <div className="flex gap-3">
              <div
                className="flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold"
                style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#f87171' }}
              >3</div>
              <div>
                <p className="text-koba-text text-sm font-medium">Block</p>
                <p className="text-koba-text-muted text-xs mt-0.5">
                  The AI is completely prevented from using this tool. No exceptions.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
