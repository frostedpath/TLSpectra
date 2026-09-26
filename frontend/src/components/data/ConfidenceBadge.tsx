import React from 'react';
import { ConfidenceLevel } from '../../types';

interface ConfidenceBadgeProps {
  confidence: ConfidenceLevel;
  className?: string;
}

export const ConfidenceBadge: React.FC<ConfidenceBadgeProps> = ({ confidence, className = '' }) => {
  const styles: Record<ConfidenceLevel, { bg: string; text: string; border: string }> = {
    'DIRECT': { bg: 'bg-emerald-50', text: 'text-secondary', border: 'border-emerald-200' },
    'HIGH CONFIDENCE': { bg: 'bg-teal-50', text: 'text-teal-700', border: 'border-teal-200' },
    'MEDIUM CONFIDENCE': { bg: 'bg-purple-50', text: 'text-accent', border: 'border-purple-200' },
    'EXTERNAL VALIDATION': { bg: 'bg-sky-50', text: 'text-sky-700', border: 'border-sky-200' },
    'UNKNOWN': { bg: 'bg-slate-50', text: 'text-semantic-unknown', border: 'border-slate-200' },
  };

  const style = styles[confidence] || styles['UNKNOWN'];

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${style.bg} ${style.text} ${style.border} ${className}`}
      title={`Evidence strength: ${confidence}`}
    >
      {confidence}
    </span>
  );
};
