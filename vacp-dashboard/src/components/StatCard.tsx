'use client';

import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  color?: 'accent' | 'success' | 'warning' | 'danger';
  subtitle?: string;
}

const colorClasses = {
  accent: 'from-koba-accent to-koba-accent-hover',
  success: 'from-koba-success to-emerald-400',
  warning: 'from-koba-warning to-amber-400',
  danger: 'from-koba-danger to-rose-400',
};

export default function StatCard({ title, value, icon: Icon, color = 'accent', subtitle }: StatCardProps) {
  return (
    <div className="bg-koba-bg-card border border-koba-border rounded-xl p-6 hover:border-koba-accent/30 transition-all">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-koba-text-secondary text-sm uppercase tracking-wider">{title}</p>
          <p className="text-3xl font-bold text-koba-text mt-2">{value}</p>
          {subtitle && (
            <p className="text-koba-text-secondary text-sm mt-1">{subtitle}</p>
          )}
        </div>
        <div className={`w-12 h-12 rounded-lg bg-gradient-to-br ${colorClasses[color]} flex items-center justify-center`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  );
}
