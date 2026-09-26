import React from 'react';

interface SkeletonPanelProps {
  lines?: number;
  className?: string;
}

export const SkeletonPanel: React.FC<SkeletonPanelProps> = ({ lines = 4, className = '' }) => {
  return (
    <div className={`bg-surface border border-border rounded-lg p-6 space-y-3 animate-pulse ${className}`}>
      <div className="h-4 bg-slate-200 rounded w-1/4"></div>
      <div className="h-3 bg-slate-100 rounded w-3/4"></div>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="h-2.5 bg-slate-100 rounded" style={{ width: `${85 - i * 10}%` }}></div>
      ))}
    </div>
  );
};
