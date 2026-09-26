import React, { useState } from 'react';
import { Finding } from '../../types';
import { SeverityBadge } from './SeverityBadge';
import { ConfidenceBadge } from './ConfidenceBadge';
import { X, ExternalLink, ThumbsUp, ThumbsDown, CheckCircle2 } from 'lucide-react';
import { api } from '../../api/client';

interface FindingDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onNavigateToSession?: (sessionId: string) => void;
}

export const FindingDrawer: React.FC<FindingDrawerProps> = ({ finding, onClose, onNavigateToSession }) => {
  const [feedback, setFeedback] = useState<string | null>(finding?.analyst_feedback || null);
  const [notes, setNotes] = useState<string>(finding?.analyst_notes || '');
  const [submitting, setSubmitting] = useState(false);
  const [saved, setSaved] = useState(false);

  if (!finding) return null;

  const handleFeedback = async (val: 'Useful' | 'Not useful') => {
    setSubmitting(true);
    try {
      await api.updateFindingFeedback(finding.finding_id, val, notes);
      setFeedback(val);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      console.error(e);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-surface border-l border-border shadow-L3 z-50 flex flex-col animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="p-5 border-b border-border flex items-start justify-between bg-elevated">
        <div>
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className="font-mono text-xs font-bold text-textPrimary">{finding.rule_id}</span>
            <SeverityBadge severity={finding.severity} />
            <ConfidenceBadge confidence={finding.confidence} />
            {finding.ml_model_id && (
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">
                {finding.ml_model_id}
              </span>
            )}
          </div>
          <h2 className="text-base font-bold text-textPrimary leading-snug">{finding.title}</h2>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-muted hover:text-textPrimary rounded hover:bg-surface transition-colors"
          aria-label="Close details"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6 text-xs">
        {/* Traceable Evidence Path */}
        <div className="p-3.5 bg-background border border-border rounded-lg space-y-2">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted">Evidence Traceability Path</div>
          <div className="flex items-center gap-2 text-xs flex-wrap font-mono">
            <span className="bg-surface px-2 py-0.5 border border-border rounded text-textPrimary font-medium">
              {finding.finding_id}
            </span>
            <span className="text-muted">→</span>
            {finding.session_id ? (
              <button
                onClick={() => onNavigateToSession && onNavigateToSession(finding.session_id!)}
                className="bg-primary/10 hover:bg-primary/20 text-primary px-2 py-0.5 border border-primary/20 rounded font-medium flex items-center gap-1 transition-colors"
              >
                <span>{finding.session_id}</span>
                <ExternalLink className="w-3 h-3" />
              </button>
            ) : (
              <span className="text-muted">Capture-wide</span>
            )}
            <span className="text-muted">→</span>
            <span className="bg-surface px-2 py-0.5 border border-border rounded text-textSecondary">
              {finding.category}
            </span>
          </div>
        </div>

        {/* Security Impact */}
        <div className="space-y-1.5">
          <h3 className="font-semibold text-textPrimary uppercase tracking-wider text-[11px] text-muted">Observed Security Impact</h3>
          <p className="text-textSecondary leading-relaxed bg-surface p-3 border border-border rounded-md">
            {finding.impact}
          </p>
        </div>

        {/* Recommended Remediation */}
        <div className="space-y-1.5">
          <h3 className="font-semibold text-textPrimary uppercase tracking-wider text-[11px] text-muted">Prioritized Remediation</h3>
          <p className="text-textSecondary leading-relaxed bg-surface p-3 border border-border rounded-md">
            {finding.recommendation}
          </p>
        </div>

        {/* Standards Reference */}
        <div className="space-y-1.5">
          <h3 className="font-semibold text-textPrimary uppercase tracking-wider text-[11px] text-muted">Authoritative Standards Reference</h3>
          <div className="p-3 bg-elevated border border-border rounded-md font-mono text-textPrimary font-medium">
            {finding.standards_ref}
          </div>
        </div>

        {/* Evidence Artifacts JSON */}
        <div className="space-y-1.5">
          <h3 className="font-semibold text-textPrimary uppercase tracking-wider text-[11px] text-muted">Raw Observable Evidence</h3>
          <pre className="p-3 bg-slate-900 text-slate-100 rounded-md font-mono text-[11px] overflow-x-auto">
            {JSON.stringify(finding.evidence_json, null, 2)}
          </pre>
        </div>

        {/* Analyst Feedback Section (Local triage) */}
        <div className="p-4 bg-elevated border border-border rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-textPrimary text-xs">Analyst Assessment Feedback</span>
            {saved && (
              <span className="flex items-center gap-1 text-[11px] text-semantic-success font-medium">
                <CheckCircle2 className="w-3.5 h-3.5" /> Saved locally
              </span>
            )}
          </div>
          <p className="text-[11px] text-muted">
            Mark whether this detection is relevant to your forensic investigation. Feedback is stored locally for audit reporting.
          </p>
          <div className="flex gap-2">
            <button
              disabled={submitting}
              onClick={() => handleFeedback('Useful')}
              className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded text-xs font-medium border transition-colors ${
                feedback === 'Useful'
                  ? 'bg-secondary text-white border-secondary'
                  : 'bg-surface hover:bg-elevated text-textPrimary border-border'
              }`}
            >
              <ThumbsUp className="w-3.5 h-3.5" />
              <span>Useful</span>
            </button>
            <button
              disabled={submitting}
              onClick={() => handleFeedback('Not useful')}
              className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded text-xs font-medium border transition-colors ${
                feedback === 'Not useful'
                  ? 'bg-slate-700 text-white border-slate-700'
                  : 'bg-surface hover:bg-elevated text-textPrimary border-border'
              }`}
            >
              <ThumbsDown className="w-3.5 h-3.5" />
              <span>Not Useful</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
