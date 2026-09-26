import React, { useEffect, useState } from 'react';
import { Capture, Finding, Session } from '../types';
import { api } from '../api/client';
import { BookOpen, Search, Code, CheckCircle2 } from 'lucide-react';
import { SkeletonPanel } from '../components/feedback/SkeletonPanel';

interface EvidenceExplorerProps {
  capture: Capture;
}

export const EvidenceExplorer: React.FC<EvidenceExplorerProps> = ({ capture }) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedItem, setSelectedItem] = useState<Finding | Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadEvidence = async () => {
      setLoading(true);
      try {
        const [fRes, sRes] = await Promise.all([
          api.getCaptureFindings(capture.capture_id, { limit: 100 }),
          api.getCaptureSessions(capture.capture_id, { limit: 100 }),
        ]);
        setFindings(fRes.items);
        setSessions(sRes.items);
        if (fRes.items.length > 0) setSelectedItem(fRes.items[0]);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };

    loadEvidence();
  }, [capture.capture_id]);

  if (loading) return <SkeletonPanel lines={8} />;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-textPrimary tracking-tight">Passive Evidence Explorer</h2>
        <p className="text-xs text-muted">
          Inspect raw observable parameters, byte field offsets, and rule validation traces.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">
        {/* Item Selector List */}
        <div className="bg-surface border border-border rounded-lg overflow-y-auto p-3 space-y-2 text-xs">
          <div className="text-[11px] font-semibold text-muted uppercase tracking-wider px-2">Findings Evidence</div>
          {findings.map((f) => (
            <button
              key={f.finding_id}
              onClick={() => setSelectedItem(f)}
              className={`w-full text-left p-2.5 rounded-md border transition-colors ${
                (selectedItem as Finding)?.finding_id === f.finding_id
                  ? 'bg-primary/10 border-primary text-primary font-semibold'
                  : 'bg-background border-border text-textPrimary hover:bg-elevated'
              }`}
            >
              <div className="font-mono text-[11px]">{f.rule_id}</div>
              <div className="truncate text-xs">{f.title}</div>
            </button>
          ))}
        </div>

        {/* JSON Evidence Inspector */}
        <div className="lg:col-span-2 bg-slate-900 text-slate-100 rounded-lg p-5 overflow-y-auto font-mono text-xs shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4 text-slate-400">
              <span className="flex items-center gap-2">
                <Code className="w-4 h-4 text-primary" />
                <span>Evidence Record Inspector</span>
              </span>
              <span className="text-[11px]">Strict Passive Proof</span>
            </div>

            <pre className="text-[11px] leading-relaxed overflow-x-auto">
              {JSON.stringify(selectedItem, null, 2)}
            </pre>
          </div>

          <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-400 italic">
            Deterministic rule assertions are derived directly from the above capture record fields.
          </div>
        </div>
      </div>
    </div>
  );
};
