import React from 'react';
import type { LucideIcon } from 'lucide-react';

interface StatSummaryProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  trendUp?: boolean;
}

export const StatSummary: React.FC<StatSummaryProps> = ({ title, value, icon: Icon, trend, trendUp }) => {
  return (
    <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-sm flex flex-col">
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">{title}</h3>
        <div className="text-primary bg-blue-50 p-1.5 rounded-md">
          <Icon className="w-4 h-4" />
        </div>
      </div>
      <div className="mt-auto flex items-end gap-3">
        <span className="text-3xl font-bold text-slate-800 tracking-tight">{value}</span>
        {trend && (
          <span className={`text-xs font-medium px-1.5 py-0.5 rounded mb-1 ${trendUp ? 'text-emerald-700 bg-emerald-50' : 'text-red-700 bg-red-50'}`}>
            {trend}
          </span>
        )}
      </div>
    </div>
  );
};
