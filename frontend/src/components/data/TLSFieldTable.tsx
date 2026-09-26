import React from 'react';
import { TLSHandshake } from '../../types';
import { Check, X, Shield, Lock, EyeOff } from 'lucide-react';

interface TLSFieldTableProps {
  handshake?: TLSHandshake;
}

export const TLSFieldTable: React.FC<TLSFieldTableProps> = ({ handshake }) => {
  if (!handshake) {
    return (
      <div className="p-6 bg-surface border border-border rounded-lg text-center text-xs text-muted">
        No TLS handshake observed for this session (unencrypted plaintext traffic).
      </div>
    );
  }

  const isTLS13 = handshake.version === 'TLS 1.3';

  return (
    <div className="bg-surface border border-border rounded-lg p-5 shadow-sm space-y-4">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <h3 className="text-sm font-semibold text-textPrimary flex items-center gap-2">
          <Lock className="w-4 h-4 text-primary" />
          <span>TLS Handshake Parameters</span>
        </h3>
        {isTLS13 && (
          <span className="flex items-center gap-1.5 px-2 py-0.5 bg-sky-50 border border-sky-200 text-primary text-[11px] font-semibold rounded">
            <EyeOff className="w-3.5 h-3.5" /> TLS 1.3 Encrypted Handshake
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
        <div className="p-3 bg-background border border-border rounded-md">
          <div className="text-[11px] font-medium text-muted">Negotiated Version</div>
          <div className="font-mono font-bold text-textPrimary mt-1 text-sm">{handshake.version || 'UNKNOWN'}</div>
        </div>

        <div className="p-3 bg-background border border-border rounded-md">
          <div className="text-[11px] font-medium text-muted">Cipher Suite</div>
          <div className="font-mono font-semibold text-textPrimary mt-1 text-xs break-all">
            {handshake.cipher_suite || 'UNKNOWN'}
          </div>
        </div>

        <div className="p-3 bg-background border border-border rounded-md">
          <div className="text-[11px] font-medium text-muted">Forward Secrecy</div>
          <div className="flex items-center gap-1.5 font-semibold mt-1">
            {handshake.forward_secrecy ? (
              <span className="text-semantic-success flex items-center gap-1">
                <Check className="w-4 h-4" /> Forward Secret (ECDHE/DHE)
              </span>
            ) : (
              <span className="text-semantic-error flex items-center gap-1">
                <X className="w-4 h-4" /> No Forward Secrecy
              </span>
            )}
          </div>
        </div>

        <div className="p-3 bg-background border border-border rounded-md">
          <div className="text-[11px] font-medium text-muted">Server Name Indication (SNI)</div>
          <div className="font-mono text-textPrimary mt-1">{handshake.sni || '<None Observable>'}</div>
        </div>

        <div className="p-3 bg-background border border-border rounded-md">
          <div className="text-[11px] font-medium text-muted">JA3 Client Fingerprint</div>
          <div className="font-mono text-[11px] text-muted truncate mt-1" title={handshake.ja3_fingerprint}>
            {handshake.ja3_fingerprint || 'N/A'}
          </div>
        </div>

        <div className="p-3 bg-background border border-border rounded-md">
          <div className="text-[11px] font-medium text-muted">JA3S Server Fingerprint</div>
          <div className="font-mono text-[11px] text-muted truncate mt-1" title={handshake.ja3s_fingerprint}>
            {handshake.ja3s_fingerprint || 'N/A'}
          </div>
        </div>
      </div>
    </div>
  );
};
