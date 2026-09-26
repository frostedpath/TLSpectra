import React, { useEffect, useState } from 'react';
import { Capture, Session } from '../types';
import { api } from '../api/client';
import { Layers, Lock, Unlock, ShieldAlert, ChevronRight } from 'lucide-react';
import { SkeletonPanel } from '../components/feedback/SkeletonPanel';
import { StartTLSStateMachine } from '../components/data/StartTLSStateMachine';
import { TLSFieldTable } from '../components/data/TLSFieldTable';
import { CertificateChain } from '../components/data/CertificateChain';

interface SessionsProps {
  capture: Capture;
  selectedSessionId?: string | null;
  onClearSelectedSession?: () => void;
}

export const Sessions: React.FC<SessionsProps> = ({
  capture,
  selectedSessionId,
  onClearSelectedSession
}) => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [totalSessions, setTotalSessions] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [activeSession, setActiveSession] = useState<Session | null>(null);
  const [protocolFilter, setProtocolFilter] = useState('');
  const [stateFilter, setStateFilter] = useState('');

  const loadSessions = async () => {
    setLoading(true);
    try {
      const res = await api.getCaptureSessions(capture.capture_id, {
        protocol: protocolFilter || undefined,
        starttls_state: stateFilter || undefined,
        limit: 200
      });
      setSessions(res.items);
      setTotalSessions(res.total);

      if (selectedSessionId) {
        const target = res.items.find((s) => s.session_id === selectedSessionId);
        if (target) {
          const fullSess = await api.getSession(target.session_id);
          setActiveSession(fullSess);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSessions();
  }, [capture.capture_id, protocolFilter, stateFilter, selectedSessionId]);

  const handleSelectSession = async (sess: Session) => {
    try {
      const full = await api.getSession(sess.session_id);
      setActiveSession(full);
    } catch (e) {
      console.error(e);
    }
  };

  if (activeSession) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                setActiveSession(null);
                if (onClearSelectedSession) onClearSelectedSession();
              }}
              className="text-xs text-primary hover:underline font-semibold"
            >
              ← Back to Sessions List
            </button>
            <span className="text-muted">•</span>
            <h2 className="text-lg font-bold text-textPrimary">Session Detail ({activeSession.session_id})</h2>
          </div>
        </div>

        {/* Session Summary Card */}
        <div className="bg-surface border border-border rounded-lg p-5 shadow-sm space-y-3 text-xs">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div>
              <div className="text-[11px] text-muted font-medium">Protocol</div>
              <div className="font-bold text-textPrimary text-sm mt-0.5">{activeSession.protocol}</div>
            </div>
            <div>
              <div className="text-[11px] text-muted font-medium">Client Endpoint</div>
              <div className="font-mono text-textPrimary mt-0.5">{activeSession.client_ip}:{activeSession.client_port}</div>
            </div>
            <div>
              <div className="text-[11px] text-muted font-medium">Server Endpoint</div>
              <div className="font-mono text-textPrimary mt-0.5">{activeSession.server_ip}:{activeSession.server_port}</div>
            </div>
            <div>
              <div className="text-[11px] text-muted font-medium">Traffic Volume</div>
              <div className="text-textSecondary mt-0.5">{activeSession.packet_count} packets • {(activeSession.byte_count / 1024).toFixed(1)} KB</div>
            </div>
          </div>

          {activeSession.auth_plaintext && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-md text-semantic-error flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0" />
              <span>
                <strong>Plaintext Authentication Detected:</strong> User credentials were submitted over an unencrypted channel. (Credential values redacted per privacy policy).
              </span>
            </div>
          )}
        </div>

        {/* STARTTLS State Machine */}
        <StartTLSStateMachine state={activeSession.starttls_state} />

        {/* TLS Handshake */}
        <TLSFieldTable handshake={activeSession.handshake} />

        {/* Certificate Chain */}
        <CertificateChain
          certificates={activeSession.handshake?.certificates || []}
          isTLS13={activeSession.handshake?.version === 'TLS 1.3'}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-textPrimary tracking-tight">Reconstructed Email Sessions</h2>
          <p className="text-xs text-muted">
            {totalSessions > sessions.length
              ? `Showing top ${sessions.length} of ${totalSessions.toLocaleString()} sessions analyzed (preview capped at ${sessions.length}).`
              : `Directional TCP streams identified for SMTP, IMAP, and POP3 (${totalSessions.toLocaleString()} total sessions).`}
          </p>
        </div>
      </div>

      {/* Filter Controls */}
      <div className="bg-surface border border-border rounded-lg p-3 flex items-center gap-3 text-xs">
        <select
          value={protocolFilter}
          onChange={(e) => setProtocolFilter(e.target.value)}
          className="bg-background border border-border rounded px-2.5 py-1.5 text-xs text-textPrimary"
        >
          <option value="">All Protocols</option>
          <option value="SMTP">SMTP</option>
          <option value="IMAP">IMAP</option>
          <option value="POP3">POP3</option>
        </select>

        <select
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value)}
          className="bg-background border border-border rounded px-2.5 py-1.5 text-xs text-textPrimary"
        >
          <option value="">All STARTTLS States</option>
          <option value="TLS_ESTABLISHED">TLS Established</option>
          <option value="CLEARTEXT_AFTER_OFFER">Cleartext After Offer</option>
          <option value="REJECTED">Rejected / Failed</option>
          <option value="NOT_OFFERED">Not Offered</option>
        </select>
      </div>

      {/* Sessions Table */}
      {loading ? (
        <SkeletonPanel lines={8} />
      ) : (
        <div className="bg-surface border border-border rounded-lg overflow-hidden shadow-sm">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-elevated border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted">
                <th className="py-3 px-4">Session ID</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Client Endpoint</th>
                <th className="py-3 px-4">Server Endpoint</th>
                <th className="py-3 px-4">STARTTLS State</th>
                <th className="py-3 px-4">Packets / Bytes</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sessions.map((s) => (
                <tr
                  key={s.session_id}
                  onClick={() => handleSelectSession(s)}
                  className="hover:bg-elevated cursor-pointer transition-colors"
                >
                  <td className="py-3 px-4 font-mono font-medium text-textPrimary">
                    {s.session_id}
                  </td>
                  <td className="py-3 px-4 font-semibold text-textPrimary">
                    {s.protocol}
                  </td>
                  <td className="py-3 px-4 font-mono text-textSecondary">
                    {s.client_ip}:{s.client_port}
                  </td>
                  <td className="py-3 px-4 font-mono text-textSecondary">
                    {s.server_ip}:{s.server_port}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-medium ${
                      s.starttls_state === 'TLS_ESTABLISHED'
                        ? 'bg-emerald-50 text-secondary'
                        : s.starttls_state === 'CLEARTEXT_AFTER_OFFER'
                        ? 'bg-red-50 text-semantic-error'
                        : 'bg-slate-100 text-muted'
                    }`}>
                      {s.starttls_state}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-textSecondary">
                    {s.packet_count} pkts • {(s.byte_count / 1024).toFixed(1)} KB
                  </td>
                  <td className="py-3 px-4 text-right text-muted">
                    <ChevronRight className="w-4 h-4 inline-block" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
