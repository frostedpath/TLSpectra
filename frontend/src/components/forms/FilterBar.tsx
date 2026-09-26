import React from 'react';
import { Filter, X } from 'lucide-react';

interface FilterOption {
  label: string;
  value: string;
}

interface FilterBarProps {
  severityFilter?: string;
  onSeverityChange?: (val: string) => void;
  categoryFilter?: string;
  onCategoryChange?: (val: string) => void;
  protocolFilter?: string;
  onProtocolChange?: (val: string) => void;
  onResetFilters: () => void;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  severityFilter,
  onSeverityChange,
  categoryFilter,
  onCategoryChange,
  protocolFilter,
  onProtocolChange,
  onResetFilters
}) => {
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const categories = ['Cryptographic Security', 'Certificate Security', 'Protocol Security', 'STARTTLS Security', 'Behavioural Anomaly'];
  const protocols = ['SMTP', 'IMAP', 'POP3'];

  const hasActiveFilters = Boolean(severityFilter || categoryFilter || protocolFilter);

  return (
    <div className="bg-surface border border-border rounded-lg p-3 flex items-center justify-between gap-3 text-xs flex-wrap">
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 text-muted font-medium mr-2">
          <Filter className="w-3.5 h-3.5" />
          <span>Filters:</span>
        </div>

        {/* Severity Filter */}
        {onSeverityChange && (
          <select
            value={severityFilter || ''}
            onChange={(e) => onSeverityChange(e.target.value)}
            className="bg-background border border-border rounded px-2.5 py-1.5 text-textPrimary text-xs focus:ring-1 focus:ring-primary"
            aria-label="Filter by Severity"
          >
            <option value="">All Severities</option>
            {severities.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        )}

        {/* Category Filter */}
        {onCategoryChange && (
          <select
            value={categoryFilter || ''}
            onChange={(e) => onCategoryChange(e.target.value)}
            className="bg-background border border-border rounded px-2.5 py-1.5 text-textPrimary text-xs focus:ring-1 focus:ring-primary"
            aria-label="Filter by Category"
          >
            <option value="">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        )}

        {/* Protocol Filter */}
        {onProtocolChange && (
          <select
            value={protocolFilter || ''}
            onChange={(e) => onProtocolChange(e.target.value)}
            className="bg-background border border-border rounded px-2.5 py-1.5 text-textPrimary text-xs focus:ring-1 focus:ring-primary"
            aria-label="Filter by Protocol"
          >
            <option value="">All Protocols</option>
            {protocols.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        )}
      </div>

      {hasActiveFilters && (
        <button
          onClick={onResetFilters}
          className="flex items-center gap-1 text-[11px] text-muted hover:text-textPrimary px-2 py-1 rounded hover:bg-elevated transition-colors"
        >
          <X className="w-3.5 h-3.5" />
          <span>Clear Filters</span>
        </button>
      )}
    </div>
  );
};
