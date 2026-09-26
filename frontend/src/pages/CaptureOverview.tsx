import React, { useEffect, useState } from 'react';
import { Capture, ScoreData, Finding, Session, Host } from '../types';
import { api } from '../api/client';
import { PostureScoreGauge } from '../components/data/PostureScoreGauge';
import { ScoreBreakdown } from '../components/data/ScoreBreakdown';
import { VisibilityLimitCallout } from '../components/data/VisibilityLimitCallout';
import { FindingTable } from '../components/data/FindingTable';
import { FindingDrawer } from '../components/data/FindingDrawer';
import { SkeletonPanel } from '../components/feedback/SkeletonPanel';
import { Shield, Layers, Server, AlertTriangle, FileText, ArrowRight } from 'lucide-react';

interface CaptureOverviewProps {
  capture: Capture;
  onNavigate: (screen: string) => void;
  onSelectSession: (sessionId: string) => void;
}

export const CaptureOverview: React.FC<CaptureOverviewProps> = ({
  capture,
  onNavigate,
  onSelectSession
}) => {
  const [scoreData, setScoreData] = useState<ScoreData | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [totalSessions, setTotalSessions] = useState<number>(0);
  const [totalFindings, setTotalFindings] = useState<number>(0);
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({});
  const [starttlsCounts, setStarttlsCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  useEffect(() => {
    const loadOverview = async () => {
      setLoading(true);
      try {
        const [scoreRes, findingsRes, sessionsRes, hostsRes] = await Promise.allSettled([
          api.getCaptureScore(capture.capture_id),
          api.getCaptureFindings(capture.capture_id, { limit: 100 }),
          api.getCaptureSessions(capture.capture_id, { limit: 100 }),
          api.getCaptureHosts(capture.capture_id),
        ]);
        if (scoreRes.status === 'fulfilled') setScoreData(scoreRes.value);
        if (findingsRes.status === 'fulfilled') {
          setFindings(findingsRes.value.items);
          setTotalFindings(findingsRes.value.total);
          setSeverityCounts(findingsRes.value.severity_counts || {});
        }
        if (sessionsRes.status === 'fulfilled') {
          setSessions(sessionsRes.value.items);
          setTotalSessions(sessionsRes.value.total);
          setStarttlsCounts(sessionsRes.value.starttls_counts || {});
        }
        if (hostsRes.status === 'fulfilled') setHosts(hostsRes.value.items);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };

    loadOverview();
  }, [capture.capture_id]);

  if (loading) {
    return (
      <div className="space-y-6">
        <SkeletonPanel lines={8} />
      </div>
    );
  }

  const effectiveTotalSessions = totalSessions > 0 ? totalSessions : sessions.length;
  const effectiveTotalFindings = totalFindings > 0 ? totalFindings : findings.length;

  const totalCritHigh = (severityCounts['CRITICAL'] || 0) + (severityCounts['HIGH'] || 0);
  const criticalHighCount = totalCritHigh > 0
    ? totalCritHigh
    : findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;

  const totalEncrypted = starttlsCounts['TLS_ESTABLISHED'] !== undefined
    ? starttlsCounts['TLS_ESTABLISHED']
    : sessions.filter((s) => s.starttls_state === 'TLS_ESTABLISHED').length;

  const starttlsCompliance = effectiveTotalSessions > 0
    ? Math.round((totalEncrypted / effectiveTotalSessions) * 100)
    : 0;

  return (
    <div className="space-y-6">
      {/* Top Action Banner */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-textPrimary tracking-tight">Security Posture Dashboard</h2>
          <p className="text-xs text-muted">
            Evidence-linked cryptographic evaluation for <strong>{capture.filename}</strong>
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={() => onNavigate('report-builder')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary hover:bg-primary-hover text-white text-xs font-semibold rounded-md shadow-sm transition-colors"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Generate Report</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        <div className="p-4 bg-surface border border-border rounded-lg shadow-sm">
          <div className="flex items-center justify-between text-muted text-xs">
            <span>Reconstructed Sessions</span>
            <Layers className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold text-textPrimary mt-2">{effectiveTotalSessions.toLocaleString()}</div>
          <div className="text-[11px] text-muted mt-1">
            {effectiveTotalSessions > sessions.length
              ? `${sessions.length} of ${effectiveTotalSessions.toLocaleString()} sessions loaded`
              : 'SMTP, IMAP, POP3'}
          </div>
        </div>

        <div className="p-4 bg-surface border border-border rounded-lg shadow-sm">
          <div className="flex items-center justify-between text-muted text-xs">
            <span>High / Critical Findings</span>
            <AlertTriangle className="w-4 h-4 text-semantic-error" />
          </div>
          <div className="text-2xl font-bold text-semantic-error mt-2">{criticalHighCount.toLocaleString()}</div>
          <div className="text-[11px] text-muted mt-1">
            Requiring remediation ({effectiveTotalFindings.toLocaleString()} total findings)
          </div>
        </div>

        <div className="p-4 bg-surface border border-border rounded-lg shadow-sm">
          <div className="flex items-center justify-between text-muted text-xs">
            <span>STARTTLS Compliance</span>
            <Shield className="w-4 h-4 text-secondary" />
          </div>
          <div className="text-2xl font-bold text-textPrimary mt-2">{starttlsCompliance}%</div>
          <div className="text-[11px] text-muted mt-1">
            {totalEncrypted.toLocaleString()} of {effectiveTotalSessions.toLocaleString()} encrypted
          </div>
        </div>

        <div className="p-4 bg-surface border border-border rounded-lg shadow-sm">
          <div className="flex items-center justify-between text-muted text-xs">
            <span>Observed Mail Hosts</span>
            <Server className="w-4 h-4 text-primary" />
          </div>
          <div className="text-2xl font-bold text-textPrimary mt-2">{hosts.length}</div>
          <div className="text-[11px] text-muted mt-1">Servers identified</div>
        </div>
      </div>

      {/* Posture Score & Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <PostureScoreGauge
            score={scoreData?.posture_score ?? 100}
            totalFindings={effectiveTotalFindings}
            totalSessions={effectiveTotalSessions}
          />
        </div>

        <div className="lg:col-span-2">
          {scoreData && (
            <ScoreBreakdown
              breakdown={scoreData.breakdown}
              disclaimer={scoreData.disclaimer}
            />
          )}
        </div>
      </div>

      {/* Visibility Limit Callout */}
      <VisibilityLimitCallout rate={capture.passive_visibility_rate} />

      {/* Key Findings Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-textPrimary">Top Priority Findings</h3>
          <button
            onClick={() => onNavigate('findings')}
            className="flex items-center gap-1 text-xs text-primary font-medium hover:underline"
          >
            <span>View All ({findings.length}) Findings</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <FindingTable
          findings={findings.slice(0, 5)}
          onSelectFinding={(f) => setSelectedFinding(f)}
        />
      </div>

      {/* Finding Detail Drawer */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onNavigateToSession={onSelectSession}
      />
    </div>
  );
};
