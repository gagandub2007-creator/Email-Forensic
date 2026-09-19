import React from 'react';

interface SectionHeaderProps {
  title: string;
  description?: string;
  badge?: string;
  action?: React.ReactNode;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({ title, description, badge, action }) => {
  return (
    <div className="flex items-center justify-between mb-4">
      <div>
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-slate-800">{title}</h2>
          {badge && (
            <span className="bg-blue-50 text-primary text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider border border-blue-100">
              {badge}
            </span>
          )}
        </div>
        {description && <p className="text-sm text-slate-500 mt-1">{description}</p>}
      </div>
      {action && <div>{action}</div>}
    </div>
  );
};
