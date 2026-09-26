import React from 'react';
import { Certificate } from '../../types';
import { Award, ShieldAlert, CheckCircle2, AlertCircle } from 'lucide-react';

interface CertificateChainProps {
  certificates: Certificate[];
  isTLS13?: boolean;
}

export const CertificateChain: React.FC<CertificateChainProps> = ({ certificates, isTLS13 }) => {
  if (certificates.length === 0) {
    if (isTLS13) {
      return (
        <div className="p-6 bg-sky-50/50 border border-sky-200 rounded-lg text-xs space-y-2">
          <div className="font-semibold text-textPrimary flex items-center gap-2">
            <Award className="w-4 h-4 text-primary" />
            <span>X.509 Certificate Chain — Encrypted under TLS 1.3</span>
          </div>
          <p className="text-textSecondary leading-relaxed">
            In TLS 1.3, the server certificate record is encrypted on the wire. Passive network captures cannot inspect X.509 fields without private keys or active endpoint agents.
          </p>
        </div>
      );
    }

    return (
      <div className="p-6 bg-surface border border-border rounded-lg text-center text-xs text-muted">
        No X.509 certificates observed in this capture session.
      </div>
    );
  }

  return (
    <div className="bg-surface border border-border rounded-lg p-5 shadow-sm space-y-4">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <h3 className="text-sm font-semibold text-textPrimary flex items-center gap-2">
          <Award className="w-4 h-4 text-secondary" />
          <span>Presented Certificate Chain ({certificates.length} Certificate{certificates.length !== 1 ? 's' : ''})</span>
        </h3>
      </div>

      <div className="space-y-4">
        {certificates.map((cert, idx) => (
          <div key={cert.cert_id} className="p-4 bg-background border border-border rounded-lg space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-bold text-textPrimary">
                {idx === 0 ? 'Leaf / Server Certificate' : `Intermediate CA #${idx}`}
              </span>
              {cert.is_self_signed && (
                <span className="px-2 py-0.5 bg-amber-100 text-amber-800 text-[11px] font-semibold rounded">
                  Self-Signed
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div>
                <div className="text-[11px] text-muted font-medium">Subject</div>
                <div className="font-mono text-textPrimary break-all mt-0.5">{cert.subject || 'N/A'}</div>
              </div>

              <div>
                <div className="text-[11px] text-muted font-medium">Issuer</div>
                <div className="font-mono text-textPrimary break-all mt-0.5">{cert.issuer || 'N/A'}</div>
              </div>

              <div>
                <div className="text-[11px] text-muted font-medium">Public Key & Algorithm</div>
                <div className="font-mono text-textPrimary mt-0.5">
                  {cert.public_key_alg} {cert.key_bits ? `(${cert.key_bits} bits)` : ''}
                </div>
              </div>

              <div>
                <div className="text-[11px] text-muted font-medium">Signature Digest Algorithm</div>
                <div className="font-mono text-textPrimary mt-0.5">{cert.signature_alg || 'N/A'}</div>
              </div>

              <div>
                <div className="text-[11px] text-muted font-medium">Validity Window</div>
                <div className="text-textSecondary mt-0.5">
                  {cert.not_before ? new Date(cert.not_before).toLocaleDateString() : 'N/A'} to{' '}
                  {cert.not_after ? new Date(cert.not_after).toLocaleDateString() : 'N/A'}
                </div>
              </div>

              <div>
                <div className="text-[11px] text-muted font-medium">Subject Alternative Names (SAN)</div>
                <div className="text-textSecondary mt-0.5">
                  {cert.san && cert.san.length > 0 ? cert.san.join(', ') : 'None'}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
