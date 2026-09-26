import React from 'react';
import { Finding } from '../../types';
import { SeverityBadge } from './SeverityBadge';
import { ConfidenceBadge } from './ConfidenceBadge';
import { ChevronRight, ShieldAlert } from 'lucide-react';

interface FindingTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
}

export const FindingTable: React.FC<FindingTableProps> = ({ findings, onSelectFinding }) => {
  if (findings.length === 0) {
    return (
      <div className="p-8 text-center bg-surface border border-border rounded-lg text-muted">
        <ShieldAlert className="w-8 h-8 mx-auto text-muted/60 mb-2" />
        <div className="text-sm font-medium text-textPrimary">No Findings Matched</div>
        <div className="text-xs mt-1">Adjust filters or select another capture to view security findings.</div>
      </div>
    );
  }

  return (
    <div className="bg-surface border border-border rounded-lg overflow-hidden shadow-sm">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse" role="table">
          <thead>
            <tr className="bg-elevated border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted">
              <th className="py-3 px-4">Rule ID</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Confidence</th>
              <th className="py-3 px-4">Title & Details</th>
              <th className="py-3 px-4">Category</th>
              <th className="py-3 px-4">Standards</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border text-xs">
            {findings.map((finding) => (
              <tr
                key={finding.finding_id}
                onClick={() => onSelectFinding(finding)}
                className="hover:bg-elevated/70 cursor-pointer transition-colors"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSelectFinding(finding);
                  }
                }}
              >
                <td className="py-3 px-4 font-mono font-medium text-textPrimary whitespace-nowrap">
                  {finding.rule_id}
                </td>
                <td className="py-3 px-4 whitespace-nowrap">
                  <SeverityBadge severity={finding.severity} />
                </td>
                <td className="py-3 px-4 whitespace-nowrap">
                  <ConfidenceBadge confidence={finding.confidence} />
                </td>
                <td className="py-3 px-4">
                  <div className="font-semibold text-textPrimary">{finding.title}</div>
                  <div className="text-[11px] text-muted line-clamp-1 mt-0.5">{finding.impact}</div>
                </td>
                <td className="py-3 px-4 text-textSecondary whitespace-nowrap">
                  {finding.category}
                </td>
                <td className="py-3 px-4 font-mono text-[11px] text-muted whitespace-nowrap">
                  {finding.standards_ref}
                </td>
                <td className="py-3 px-4 text-right text-muted">
                  <ChevronRight className="w-4 h-4 inline-block" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
