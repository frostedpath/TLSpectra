import React, { useEffect, useState } from 'react';
import { Capture, Host } from '../types';
import { api } from '../api/client';
import { Server, Shield } from 'lucide-react';
import { SkeletonPanel } from '../components/feedback/SkeletonPanel';

interface HostsProps {
  capture: Capture;
}

export const Hosts: React.FC<HostsProps> = ({ capture }) => {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadHosts = async () => {
      setLoading(true);
      try {
        const res = await api.getCaptureHosts(capture.capture_id);
        setHosts(res.items);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };

    loadHosts();
  }, [capture.capture_id]);

  if (loading) {
    return <SkeletonPanel lines={6} />;
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-textPrimary tracking-tight">Observed Mail Hosts</h2>
        <p className="text-xs text-muted">
          Server IP addresses and hostnames identified across <strong>{capture.filename}</strong>
        </p>
      </div>

      <div className="bg-surface border border-border rounded-lg overflow-hidden shadow-sm">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-elevated border-b border-border text-[11px] font-semibold uppercase tracking-wider text-muted">
              <th className="py-3 px-4">Host IP Address</th>
              <th className="py-3 px-4">Observable Hostname (SNI)</th>
              <th className="py-3 px-4">Observed Sessions</th>
              <th className="py-3 px-4">Host Posture Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {hosts.map((host) => (
              <tr key={host.host_id} className="hover:bg-elevated/50">
                <td className="py-3 px-4 font-mono font-medium text-textPrimary">
                  {host.ip}
                </td>
                <td className="py-3 px-4 text-textSecondary font-mono">
                  {host.hostname || '<None Observable>'}
                </td>
                <td className="py-3 px-4 text-textSecondary">
                  {host.session_count} session{host.session_count !== 1 ? 's' : ''}
                </td>
                <td className="py-3 px-4">
                  {host.posture_score !== undefined && host.posture_score !== null ? (
                    <span className={`px-2 py-0.5 rounded font-bold text-xs ${
                      host.posture_score >= 80 ? 'bg-semantic-success text-white' : host.posture_score >= 50 ? 'bg-semantic-warning text-white' : 'bg-semantic-error text-white'
                    }`}>
                      {host.posture_score}/100
                    </span>
                  ) : (
                    <span className="text-muted text-[11px]">N/A</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
