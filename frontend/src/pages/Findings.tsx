import React, { useEffect, useState } from 'react';
import { Capture, Finding } from '../types';
import { api } from '../api/client';
import { FindingTable } from '../components/data/FindingTable';
import { FindingDrawer } from '../components/data/FindingDrawer';
import { FilterBar } from '../components/forms/FilterBar';
import { SearchInput } from '../components/forms/SearchInput';
import { SkeletonPanel } from '../components/feedback/SkeletonPanel';

interface FindingsProps {
  capture: Capture;
  onSelectSession: (sessionId: string) => void;
}

export const Findings: React.FC<FindingsProps> = ({ capture, onSelectSession }) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [totalFindings, setTotalFindings] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const res = await api.getCaptureFindings(capture.capture_id, {
        severity: severityFilter || undefined,
        category: categoryFilter || undefined,
        protocol: protocolFilter || undefined,
        limit: 200,
      });
      setFindings(res.items);
      setTotalFindings(res.total);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, [capture.capture_id, severityFilter, categoryFilter, protocolFilter]);

  const filteredFindings = findings.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.rule_id.toLowerCase().includes(q) ||
      f.title.toLowerCase().includes(q) ||
      f.impact.toLowerCase().includes(q) ||
      f.category.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-textPrimary tracking-tight">Security Findings</h2>
          <p className="text-xs text-muted">
            {totalFindings > findings.length
              ? `Showing top ${findings.length} of ${totalFindings.toLocaleString()} findings across capture ${capture.filename} (preview capped at ${findings.length}).`
              : `All deterministic rule and anomaly detections across capture ${capture.filename} (${totalFindings.toLocaleString()} total findings).`}
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <SearchInput
            value={searchQuery}
            onChange={setSearchQuery}
            placeholder="Search by rule ID, title, or keywords..."
            className="flex-1"
          />
        </div>

        <FilterBar
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          categoryFilter={categoryFilter}
          onCategoryChange={setCategoryFilter}
          protocolFilter={protocolFilter}
          onProtocolChange={setProtocolFilter}
          onResetFilters={() => {
            setSeverityFilter('');
            setCategoryFilter('');
            setProtocolFilter('');
            setSearchQuery('');
          }}
        />
      </div>

      {/* Findings Table */}
      {loading ? (
        <SkeletonPanel lines={10} />
      ) : (
        <FindingTable
          findings={filteredFindings}
          onSelectFinding={(f) => setSelectedFinding(f)}
        />
      )}

      {/* Finding Detail Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onNavigateToSession={onSelectSession}
      />
    </div>
  );
};
