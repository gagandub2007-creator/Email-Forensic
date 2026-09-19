import React from 'react';

type Status = 'OPEN' | 'CLOSED' | 'UNDER REVIEW' | 'PENDING';

interface StatusBadgeProps {
  status: Status;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const getStyles = () => {
    switch (status) {
      case 'OPEN':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'CLOSED':
        return 'bg-slate-100 text-slate-600 border-slate-200';
      case 'UNDER REVIEW':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'PENDING':
        return 'bg-purple-50 text-purple-700 border-purple-200';
      default:
        return 'bg-slate-50 text-slate-600 border-slate-200';
    }
  };

  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold border uppercase tracking-wider ${getStyles()}`}>
      {status}
    </span>
  );
};
