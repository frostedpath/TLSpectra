import React from 'react';
import { Capture, ScoreData } from '../../types';
import { Shield, Eye, Clock, X } from 'lucide-react';

interface CaptureContextBarProps {
  capture: Capture;
  score?: ScoreData;
  onClearCapture: () => void;
}

export const CaptureContextBar: React.FC<CaptureContextBarProps> = ({ capture, score, onClearCapture }) => {
  const getScoreColor = (val?: number) => {
    if (val === undefined) return 'bg-muted text-white';
    if (val >= 80) return 'bg-semantic-success text-white';
    if (val >= 50) return 'bg-semantic-warning text-white';
    return 'bg-semantic-error text-white';
  };

  return (
    <div className="bg-elevated border-b border-border px-6 py-2.5 flex items-center justify-between text-xs">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-textPrimary">{capture.filename}</span>
          <span className="text-[11px] font-mono text-muted">({capture.capture_id})</span>
        </div>

        {/* Posture Score Pill */}
        <div className="flex items-center gap-1.5 pl-3 border-l border-border">
          <Shield className="w-3.5 h-3.5 text-primary" />
          <span className="text-muted">Posture:</span>
          <span className={`px-2 py-0.5 rounded font-bold text-xs ${getScoreColor(score?.posture_score)}`}>
            {score ? `${score.posture_score}/100` : 'Calculating...'}
          </span>
        </div>

        {/* Passive Visibility Rate */}
        <div className="flex items-center gap-1.5 pl-3 border-l border-border" title="Percentage of expected TLS fields observable passively">
          <Eye className="w-3.5 h-3.5 text-secondary" />
          <span className="text-muted">Passive Visibility:</span>
          <span className="font-semibold text-textPrimary">
            {Math.round(capture.passive_visibility_rate * 100)}%
          </span>
        </div>

        {/* Status */}
        <div className="flex items-center gap-1.5 pl-3 border-l border-border text-muted">
          <Clock className="w-3.5 h-3.5" />
          <span className="capitalize">{capture.status.toLowerCase()}</span>
        </div>
      </div>

      <button
        onClick={onClearCapture}
        className="text-muted hover:text-textPrimary p-1 rounded hover:bg-surface transition-colors"
        title="Close capture context"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
};
