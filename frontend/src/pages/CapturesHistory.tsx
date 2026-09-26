import React, { useEffect, useState } from 'react';
import { Capture, ScoreData } from '../types';
import { api } from '../api/client';
import { History, FileCheck, Trash2, ArrowRight, RefreshCw, Shield } from 'lucide-react';
import { EmptyState } from '../components/feedback/EmptyState';
import { SkeletonPanel } from '../components/feedback/SkeletonPanel';

interface CapturesHistoryProps {
  onSelectCapture: (capture: Capture) => void;
  onNavigateToUpload: () => void;
}

export const CapturesHistory: React.FC<CapturesHistoryProps> = ({
  onSelectCapture,
  onNavigateToUpload
}) => {
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [scoresMap, setScoresMap] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await api.listCaptures(100);
      setCaptures(res.items);

      // Fetch scores for completed captures
      const scores: Record<string, number> = {};
      for (const cap of res.items) {
        if (cap.status === 'COMPLETE') {
          try {
            const scoreData = await api.getCaptureScore(cap.capture_id);
            scores[cap.capture_id] = scoreData.posture_score;
          } catch (e) {
            // score not yet ready
          }
        }
      }
      setScoresMap(scores);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    if (!window.confirm('Delete this capture and all associated security evidence?')) return;
    setDeletingId(id);
    try {
      await api.deleteCapture(id);
      setCaptures((prev) => prev.filter((c) => c.capture_id !== id));
    } catch (err) {
      console.error(err);
    } finally {
      setDeletingId(null);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <SkeletonPanel lines={6} />
      </div>
    );
  }

  if (captures.length === 0) {
    return (
      <EmptyState
        icon={History}
        title="No Packet Captures Found"
        description="Upload a PCAP capture to begin cryptographic posture assessment."
        actionLabel="Intake New Capture"
        onAction={onNavigateToUpload}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-textPrimary">Historical Captures</h2>
          <p className="text-xs text-muted">All uploaded network traffic files and assessment results.</p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-surface border border-border rounded-md text-xs text-textSecondary hover:bg-elevated transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      <div className="bg-surface border border-border rounded-lg overflow-hidden shadow-sm">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-elevated border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted">
              <th className="py-3 px-4">Capture ID & File</th>
              <th className="py-3 px-4">Size</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Posture Score</th>
              <th className="py-3 px-4">Uploaded Date</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {captures.map((cap) => {
              const score = scoresMap[cap.capture_id];
              return (
                <tr
                  key={cap.capture_id}
                  onClick={() => onSelectCapture(cap)}
                  className="hover:bg-elevated cursor-pointer transition-colors"
                >
                  <td className="py-3 px-4">
                    <div className="font-semibold text-textPrimary">{cap.filename}</div>
                    <div className="text-[11px] font-mono text-muted">{cap.capture_id}</div>
                  </td>
                  <td className="py-3 px-4 text-textSecondary font-mono">
                    {(cap.size_bytes / 1024).toFixed(1)} KB
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                      cap.status === 'COMPLETE' ? 'bg-emerald-50 text-secondary' : 'bg-amber-50 text-semantic-warning'
                    }`}>
                      {cap.status}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    {score !== undefined ? (
                      <span className={`px-2 py-0.5 rounded font-bold text-xs ${
                        score >= 80 ? 'bg-semantic-success text-white' : score >= 50 ? 'bg-semantic-warning text-white' : 'bg-semantic-error text-white'
                      }`}>
                        {score}/100
                      </span>
                    ) : (
                      <span className="text-muted text-[11px]">N/A</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-textSecondary">
                    {new Date(cap.uploaded_at).toLocaleString()}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      disabled={deletingId === cap.capture_id}
                      onClick={(e) => handleDelete(e, cap.capture_id)}
                      className="p-1.5 text-muted hover:text-semantic-error rounded hover:bg-surface transition-colors"
                      title="Delete capture"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
