import React, { useEffect, useState } from 'react';
import { Capture } from '../types';
import { api } from '../api/client';
import { Loader2, CheckCircle2, AlertCircle, Shield } from 'lucide-react';

interface ProcessingProps {
  capture: Capture;
  onProcessingComplete: (completedCapture: Capture) => void;
  onProcessingFailed: (errorMsg: string) => void;
}

export const Processing: React.FC<ProcessingProps> = ({
  capture,
  onProcessingComplete,
  onProcessingFailed
}) => {
  const [currentStage, setCurrentStage] = useState<string>(capture.processing_stage || 'QUEUED');
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  const stages = [
    { id: 'READING_PCAP', label: '1. Streaming Packet Frames & Ingestion' },
    { id: 'REASSEMBLING_STREAMS', label: '2. Reconstructing Directional TCP Flows' },
    { id: 'EVALUATING_RULES', label: '3. Evaluating 21 Deterministic Security Rules' },
    { id: 'RUNNING_ANOMALY_DETECTION', label: '4. Running Local Anomaly Detection' },
    { id: 'CALCULATING_SCORES', label: '5. Computing Posture Scores & Audit Trail' },
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);

    const pollInterval = setInterval(async () => {
      try {
        const updated = await api.getCapture(capture.capture_id);
        setCurrentStage(updated.processing_stage);

        if (updated.status === 'COMPLETE') {
          clearInterval(pollInterval);
          clearInterval(timer);
          onProcessingComplete(updated);
        } else if (updated.status === 'FAILED') {
          clearInterval(pollInterval);
          clearInterval(timer);
          onProcessingFailed(updated.error_message || 'Processing failed');
        }
      } catch (e) {
        console.error('Polling error', e);
      }
    }, 1200);

    return () => {
      clearInterval(pollInterval);
      clearInterval(timer);
    };
  }, [capture.capture_id]);

  const getStageIndex = (stage: string) => {
    const map: Record<string, number> = {
      'QUEUED': 0,
      'READING_PCAP': 1,
      'REASSEMBLING_STREAMS': 2,
      'EVALUATING_RULES': 3,
      'RUNNING_ANOMALY_DETECTION': 4,
      'CALCULATING_SCORES': 5,
      'COMPLETE': 6,
    };
    return map[stage] || 1;
  };

  const activeIdx = getStageIndex(currentStage);

  return (
    <div className="max-w-2xl mx-auto py-8 space-y-6">
      <div className="text-center space-y-2">
        <div className="w-12 h-12 rounded-full bg-primary/10 text-primary flex items-center justify-center mx-auto animate-pulse">
          <Loader2 className="w-6 h-6 animate-spin" />
        </div>
        <h2 className="text-lg font-bold text-textPrimary">Processing Evidence Pipeline</h2>
        <p className="text-xs text-muted">
          Analyzing <strong>{capture.filename}</strong> ({capture.capture_id}) • Elapsed: {elapsedSeconds}s
        </p>
      </div>

      {/* Stepper Card */}
      <div className="bg-surface border border-border rounded-xl p-6 shadow-sm space-y-4">
        <div className="space-y-3">
          {stages.map((stage, idx) => {
            const isDone = activeIdx > idx + 1;
            const isCurrent = activeIdx === idx + 1;

            return (
              <div
                key={stage.id}
                className={`p-3.5 rounded-lg border text-xs flex items-center justify-between transition-colors ${
                  isDone
                    ? 'bg-emerald-50/60 border-emerald-200 text-emerald-900'
                    : isCurrent
                    ? 'bg-primary/5 border-primary/30 text-primary font-semibold'
                    : 'bg-background border-border text-muted'
                }`}
              >
                <span>{stage.label}</span>
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-secondary shrink-0" />
                ) : isCurrent ? (
                  <Loader2 className="w-4 h-4 text-primary animate-spin shrink-0" />
                ) : (
                  <span className="w-2 h-2 rounded-full bg-slate-200" />
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
