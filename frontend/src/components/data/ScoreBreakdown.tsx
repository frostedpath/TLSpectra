import React from 'react';
import { ScoreBreakdownItem } from '../../types';

interface ScoreBreakdownProps {
  breakdown: ScoreBreakdownItem[];
  disclaimer: string;
}

export const ScoreBreakdown: React.FC<ScoreBreakdownProps> = ({ breakdown, disclaimer }) => {
  const categoryMaxWeights: Record<string, number> = {
    'Protocol Security': 25,
    'Cryptographic Security': 30,
    'Certificate Security': 25,
    'STARTTLS Security': 15,
    'Behavioural Anomaly': 5,
  };

  return (
    <div className="bg-surface border border-border rounded-lg p-5 shadow-sm space-y-4">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <h2 className="text-sm font-semibold text-textPrimary">Risk Contribution & Deductions</h2>
        <span className="text-[11px] text-muted">Grouped related findings</span>
      </div>

      <div className="space-y-3">
        {breakdown.map((item) => {
          const maxWeight = categoryMaxWeights[item.category] || 25;
          const pctDeducted = Math.min(100, Math.round((item.deduction / maxWeight) * 100));

          return (
            <div key={item.category} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium text-textPrimary">{item.category}</span>
                <span className="font-mono text-textSecondary">
                  <strong className={item.deduction > 0 ? 'text-semantic-error' : 'text-semantic-success'}>
                    -{item.deduction}
                  </strong>
                  {' '}/ max {maxWeight} pts
                </span>
              </div>

              {/* Progress bar */}
              <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden flex">
                <div
                  className={`h-full transition-all duration-500 ${
                    item.deduction > 0 ? 'bg-semantic-error' : 'bg-semantic-success'
                  }`}
                  style={{ width: `${pctDeducted}%` }}
                />
              </div>

              <div className="flex items-center justify-between text-[11px] text-muted">
                <span>{item.findings_count} finding{item.findings_count !== 1 ? 's' : ''}</span>
                <span>{item.grouped_rules.length > 0 ? item.grouped_rules.join(', ') : 'No findings'}</span>
              </div>
            </div>
          );
        })}
      </div>

      <div className="pt-3 border-t border-border text-[11px] text-muted italic leading-relaxed">
        <strong>Disclaimer:</strong> {disclaimer}
      </div>
    </div>
  );
};
