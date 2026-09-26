import React from 'react';
import { SeverityLevel } from '../../types';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  className?: string;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className = '' }) => {
  const styles: Record<SeverityLevel, string> = {
    CRITICAL: 'bg-red-50 text-semantic-error border-red-200',
    HIGH: 'bg-amber-50 text-semantic-warning border-amber-200',
    MEDIUM: 'bg-blue-50 text-primary border-blue-200',
    LOW: 'bg-slate-50 text-textSecondary border-slate-200',
    INFO: 'bg-slate-50 text-muted border-slate-200',
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold tracking-wide border uppercase ${styles[severity] || styles.INFO} ${className}`}
    >
      {severity}
    </span>
  );
};
