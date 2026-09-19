import React from 'react';

type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NEUTRALIZED' | 'CLEAN';

interface RiskBadgeProps {
  level: RiskLevel;
  score?: number;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, score }) => {
  const getStyles = () => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-700 border-red-200';
      case 'HIGH':
        return 'bg-amber-100 text-amber-700 border-amber-200';
      case 'MEDIUM':
        return 'bg-blue-100 text-blue-700 border-blue-200';
      case 'LOW':
      case 'CLEAN':
      case 'NEUTRALIZED':
        return 'bg-emerald-100 text-emerald-700 border-emerald-200';
      default:
        return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-semibold border ${getStyles()}`}>
      {level}
      {score !== undefined && <span className="opacity-75 font-bold">{score}</span>}
    </span>
  );
};
