import React, { useState } from 'react';
import { Capture } from '../types';
import { api } from '../api/client';
import { FileText, Download, AlertCircle, Check, Loader2 } from 'lucide-react';

interface ReportBuilderProps {
  capture: Capture;
}

export const ReportBuilder: React.FC<ReportBuilderProps> = ({ capture }) => {
  const [format, setFormat] = useState<'html' | 'json' | 'pdf'>('html');
  const [downloading, setDownloading] = useState(false);

  const sections = [
    '1. Executive Summary',
    '2. Capture Metadata and Limitations',
    '3. Protocol & Session Distribution',
    '4. STARTTLS/STLS Transition Analysis',
    '5. TLS-Version & Cipher Distribution',
    '6. Certificate Health and Identity Checks',
    '7. Cryptographic Findings',
    '8. Behavioural Anomaly Findings',
    '9. Per-Host and Overall Posture Score',
    '10. Prioritized Recommendations',
    '11. Evidence Appendix & Traceability',
    '12. Methodology and Limitations'
  ];

  const handleDownload = async () => {
    setDownloading(true);
    try {
      if (format === 'json') {
        const data = await api.getReport(capture.capture_id, 'json');
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        _triggerDownload(blob, `report_${capture.capture_id}.json`);
      } else if (format === 'html') {
        const html = await api.getReport(capture.capture_id, 'html');
        const blob = new Blob([html], { type: 'text/html' });
        _triggerDownload(blob, `report_${capture.capture_id}.html`);
      } else if (format === 'pdf') {
        const pdfBlob = await api.getReport(capture.capture_id, 'pdf');
        _triggerDownload(pdfBlob, `report_${capture.capture_id}.pdf`);
      }
    } catch (e) {
      console.error(e);
      alert('Report download failed');
    } finally {
      setDownloading(false);
    }
  };

  const _triggerDownload = (blob: Blob, filename: string) => {
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-textPrimary tracking-tight">Report Builder</h2>
        <p className="text-xs text-muted">
          Export an authoritative, evidence-linked compliance and forensic report for <strong>{capture.filename}</strong>.
        </p>
      </div>

      {/* Export Warning Callout */}
      <div className="p-4 bg-amber-50/70 border border-amber-300 rounded-lg flex items-start gap-3 text-xs text-amber-900">
        <AlertCircle className="w-4 h-4 text-semantic-warning shrink-0 mt-0.5" />
        <div>
          <div className="font-semibold">Investigation & Privacy Notice</div>
          <p className="mt-0.5 leading-relaxed">
            Reports may contain hostnames, IP addresses, packet references, and security findings. Store and share them according to your organization's investigation and privacy policy.
          </p>
        </div>
      </div>

      {/* Section Checklist */}
      <div className="bg-surface border border-border rounded-lg p-5 shadow-sm space-y-3 text-xs">
        <div className="font-semibold text-textPrimary">Included Report Sections (All 12 Mandatory Compliance Sections)</div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-textSecondary">
          {sections.map((sec, i) => (
            <div key={i} className="flex items-center gap-2 p-2 bg-background border border-border rounded">
              <Check className="w-3.5 h-3.5 text-secondary" />
              <span>{sec}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Format Selection & Download */}
      <div className="bg-surface border border-border rounded-lg p-5 shadow-sm space-y-4 text-xs">
        <div className="font-semibold text-textPrimary">Export Format</div>

        <div className="grid grid-cols-3 gap-3">
          <button
            onClick={() => setFormat('html')}
            className={`p-3 rounded-lg border text-center transition-colors ${
              format === 'html' ? 'bg-primary/10 border-primary text-primary font-bold' : 'bg-background border-border text-textSecondary hover:bg-elevated'
            }`}
          >
            HTML Document
          </button>
          <button
            onClick={() => setFormat('json')}
            className={`p-3 rounded-lg border text-center transition-colors ${
              format === 'json' ? 'bg-primary/10 border-primary text-primary font-bold' : 'bg-background border-border text-textSecondary hover:bg-elevated'
            }`}
          >
            Structured JSON
          </button>
          <button
            onClick={() => setFormat('pdf')}
            className={`p-3 rounded-lg border text-center transition-colors ${
              format === 'pdf' ? 'bg-primary/10 border-primary text-primary font-bold' : 'bg-background border-border text-textSecondary hover:bg-elevated'
            }`}
          >
            PDF Report
          </button>
        </div>

        <button
          disabled={downloading}
          onClick={handleDownload}
          className="w-full flex items-center justify-center gap-2 py-2.5 px-4 bg-primary hover:bg-primary-hover text-white text-xs font-semibold rounded-md shadow-sm transition-colors"
        >
          {downloading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Download className="w-4 h-4" />
          )}
          <span>Download {format.toUpperCase()} Report</span>
        </button>
      </div>
    </div>
  );
};
