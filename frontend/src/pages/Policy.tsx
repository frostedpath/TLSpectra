import React, { useEffect, useState } from 'react';
import { Policy } from '../types';
import { api } from '../api/client';
import { Shield, Check, Save, RotateCcw } from 'lucide-react';
import { SkeletonPanel } from '../components/feedback/SkeletonPanel';

export const PolicyEditor: React.FC = () => {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const loadPolicy = async () => {
      setLoading(true);
      try {
        const p = await api.getPolicy();
        setPolicy(p);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    loadPolicy();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policy) return;
    try {
      const updated = await api.updatePolicy(policy);
      setPolicy(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e) {
      console.error(e);
      alert('Failed to save policy');
    }
  };

  if (loading || !policy) return <SkeletonPanel lines={6} />;

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-textPrimary tracking-tight">Assessment Policy</h2>
          <p className="text-xs text-muted">
            Configure security thresholds and rule parameters for cryptographic evaluation.
          </p>
        </div>
        {saved && (
          <span className="flex items-center gap-1 text-xs text-semantic-success font-semibold">
            <Check className="w-4 h-4" /> Policy Saved
          </span>
        )}
      </div>

      <form onSubmit={handleSave} className="bg-surface border border-border rounded-lg p-6 shadow-sm space-y-5 text-xs">
        <div className="space-y-4">
          <div className="space-y-1">
            <label className="font-semibold text-textPrimary">Minimum Permitted TLS Version</label>
            <select
              value={policy.tls_min_version}
              onChange={(e) => setPolicy({ ...policy, tls_min_version: e.target.value })}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-xs text-textPrimary"
            >
              <option value="TLS 1.2">TLS 1.2 (Default - NIST SP 800-52)</option>
              <option value="TLS 1.3">TLS 1.3 (Strict)</option>
              <option value="TLS 1.0">TLS 1.0 (Permissive)</option>
            </select>
          </div>

          <div className="space-y-1">
            <label className="font-semibold text-textPrimary">Maximum Certificate Validity (Days)</label>
            <input
              type="number"
              value={policy.cert_max_validity_days}
              onChange={(e) => setPolicy({ ...policy, cert_max_validity_days: parseInt(e.target.value) || 398 })}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-xs text-textPrimary"
            />
            <span className="text-[11px] text-muted">Policy threshold for CERT-009 rule (default: 398 days).</span>
          </div>

          <div className="space-y-1">
            <label className="font-semibold text-textPrimary">Minimum RSA Key Length (Bits)</label>
            <input
              type="number"
              value={policy.rsa_min_key_bits}
              onChange={(e) => setPolicy({ ...policy, rsa_min_key_bits: parseInt(e.target.value) || 2048 })}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-xs text-textPrimary"
            />
          </div>

          <div className="space-y-1">
            <label className="font-semibold text-textPrimary">Handshake Alert Failure Threshold</label>
            <input
              type="number"
              value={policy.repeated_failures_threshold}
              onChange={(e) => setPolicy({ ...policy, repeated_failures_threshold: parseInt(e.target.value) || 3 })}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-xs text-textPrimary"
            />
            <span className="text-[11px] text-muted">Threshold for TLS-007 rule (default: 3 failures).</span>
          </div>
        </div>

        <div className="pt-4 border-t border-border flex justify-end">
          <button
            type="submit"
            className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary-hover text-white text-xs font-semibold rounded-md shadow-sm transition-colors"
          >
            <Save className="w-4 h-4" />
            <span>Save Active Policy</span>
          </button>
        </div>
      </form>
    </div>
  );
};
