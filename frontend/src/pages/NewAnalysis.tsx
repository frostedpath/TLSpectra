import React, { useState } from 'react';
import { FileDropzone } from '../components/forms/FileDropzone';
import { VisibilityLimitCallout } from '../components/data/VisibilityLimitCallout';
import { api } from '../api/client';
import { Capture } from '../types';
import { PlayCircle, ShieldCheck, FileCheck, ArrowRight } from 'lucide-react';

interface NewAnalysisProps {
  onCaptureCreated: (capture: Capture) => void;
  onSelectExistingCapture: (capture: Capture) => void;
  recentCaptures: Capture[];
}

export const NewAnalysis: React.FC<NewAnalysisProps> = ({
  onCaptureCreated,
  onSelectExistingCapture,
  recentCaptures
}) => {
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const handleUpload = async (file: File) => {
    setUploading(true);
    setUploadError(null);
    try {
      const cap = await api.uploadCapture(file);
      onCaptureCreated(cap);
    } catch (err: any) {
      setUploadError(err.message || 'Capture upload failed');
      setUploading(false);
    }
  };

  const handleLoadDemo = async (demoType: 'corpus' | 'dropzone') => {
    setUploading(true);
    setUploadError(null);
    try {
      const cap = await api.loadDemoCapture(demoType);
      onSelectExistingCapture(cap);
    } catch (err: any) {
      // Fallback: check if already in recent captures
      const targetName = demoType === 'corpus' ? 'securemailscope_demo_corpus.pcap' : 'live_dropzone_test.pcap';
      const existing = recentCaptures.find(c => c.filename === targetName && c.status === 'COMPLETE');
      if (existing) {
        onSelectExistingCapture(existing);
      } else {
        setUploadError(err.message || 'Failed to load demo capture');
      }
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Intro Header */}
      <div className="space-y-1.5">
        <div className="flex items-center gap-2">
          <h2 className="text-xl font-bold text-textPrimary tracking-tight">TLSpectra</h2>
          <span className="text-[11px] px-2 py-0.5 rounded bg-primary/10 text-primary font-semibold tracking-wide uppercase">Forensic Intake</span>
        </div>
        <div className="text-sm font-medium text-textPrimary">Evidence-Driven Cryptographic Network Forensics</div>
        <p className="text-xs text-textSecondary">
          Upload an email network traffic capture (.pcap / .pcapng) to extract TLS parameters, verify STARTTLS state machines, and calculate an evidence-linked cryptographic posture.
        </p>
      </div>

      {/* Main Upload Dropzone */}
      <FileDropzone onFileSelected={handleUpload} disabled={uploading} />

      {/* One-Click Demonstration Buttons */}
      <div className="bg-surface border border-border rounded-xl p-5 shadow-sm space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <PlayCircle className="w-4 h-4 text-primary" />
            <span className="text-xs font-bold text-textPrimary tracking-wide uppercase">One-Click Demonstration Captures</span>
          </div>
          <span className="text-[11px] text-muted font-medium">Instant analysis — no file selection needed</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
          {/* Demo 1: 150-Session Benchmark Corpus */}
          <button
            onClick={() => handleLoadDemo('corpus')}
            disabled={uploading}
            className="text-left p-4 rounded-lg border border-primary/20 bg-primary/5 hover:bg-primary/10 transition-all group flex flex-col justify-between shadow-sm cursor-pointer"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-bold text-primary flex items-center gap-1.5">
                  <PlayCircle className="w-4 h-4" /> 150-Session Ground-Truth Corpus
                </span>
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-emerald-50 text-secondary border border-emerald-200">
                  Score: 65/100
                </span>
              </div>
              <p className="text-[11px] text-textSecondary leading-relaxed">
                Full SIH reference dataset covering 6 scenario categories (Secure, Legacy, Certificate, STARTTLS, Anomaly, Malformed).
              </p>
            </div>
            <div className="mt-3 flex items-center text-[11px] font-semibold text-primary gap-1 group-hover:translate-x-0.5 transition-transform">
              <span>Load 150-Session Assessment</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </div>
          </button>

          {/* Demo 2: Live Dropzone Test Capture */}
          <button
            onClick={() => handleLoadDemo('dropzone')}
            disabled={uploading}
            className="text-left p-4 rounded-lg border border-border bg-surface hover:bg-elevated transition-all group flex flex-col justify-between shadow-sm cursor-pointer"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-bold text-textPrimary flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-secondary" /> Live Sample Dropzone Capture
                </span>
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-amber-50 text-semantic-warning border border-amber-200">
                  Score: 30/100
                </span>
              </div>
              <p className="text-[11px] text-textSecondary leading-relaxed">
                Multi-flow live capture featuring SMTP + STARTTLS (TLS 1.3), SMTPS, IMAPS, Plaintext Auth violation, and Deprecated TLS 1.0.
              </p>
            </div>
            <div className="mt-3 flex items-center text-[11px] font-semibold text-textPrimary gap-1 group-hover:translate-x-0.5 transition-transform">
              <span>Inspect Live Sample Capture</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </div>
          </button>
        </div>
      </div>

      {uploadError && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-md text-xs text-semantic-error">
          {uploadError}
        </div>
      )}

      {/* Passive Visibility Notice */}
      <VisibilityLimitCallout />

      {/* Recent Captures Quick Access */}
      {recentCaptures.length > 0 && (
        <div className="bg-surface border border-border rounded-lg p-5 shadow-sm space-y-3">
          <div className="text-xs font-semibold text-textPrimary flex items-center justify-between">
            <span>Recent Captures</span>
            <span className="text-muted text-[11px]">Ready for assessment</span>
          </div>

          <div className="divide-y divide-border">
            {recentCaptures.slice(0, 5).map((cap) => (
              <div
                key={cap.capture_id}
                onClick={() => onSelectExistingCapture(cap)}
                className="py-2.5 flex items-center justify-between hover:bg-elevated px-2 rounded cursor-pointer transition-colors text-xs"
              >
                <div className="flex items-center gap-2.5">
                  <FileCheck className="w-4 h-4 text-primary shrink-0" />
                  <div>
                    <div className="font-medium text-textPrimary">{cap.filename}</div>
                    <div className="text-[11px] text-muted font-mono">{cap.capture_id} • {(cap.size_bytes / 1024).toFixed(1)} KB</div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                    cap.status === 'COMPLETE' ? 'bg-emerald-50 text-secondary' : 'bg-amber-50 text-semantic-warning'
                  }`}>
                    {cap.status}
                  </span>
                  <ArrowRight className="w-4 h-4 text-muted" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
