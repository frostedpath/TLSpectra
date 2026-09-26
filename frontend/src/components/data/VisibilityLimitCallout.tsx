import React from 'react';
import { EyeOff, Info } from 'lucide-react';

interface VisibilityLimitCalloutProps {
  rate?: number;
  className?: string;
}

export const VisibilityLimitCallout: React.FC<VisibilityLimitCalloutProps> = ({ rate, className = '' }) => {
  return (
    <div className={`p-4 bg-sky-50/60 border border-sky-200 rounded-lg flex items-start gap-3 text-xs ${className}`}>
      <EyeOff className="w-4 h-4 text-primary shrink-0 mt-0.5" />
      <div>
        <div className="font-semibold text-textPrimary flex items-center gap-2">
          <span>TLS 1.3 Passive Visibility Boundary</span>
          {rate !== undefined && (
            <span className="text-[11px] font-mono font-medium px-1.5 py-0.5 bg-white border border-sky-300 rounded text-primary">
              {Math.round(rate * 100)}% Overall Observable
            </span>
          )}
        </div>
        <p className="text-textSecondary mt-1 leading-relaxed">
          In TLS 1.3 (RFC 8446), Server Certificate and Handshake Extension records are encrypted under initial handshake keys.
          In passive PCAP captures, these fields cannot be extracted and are designated as <code className="bg-white px-1 py-0.5 border border-sky-200 rounded text-[11px]">NOT_OBSERVABLE</code>.
          <strong> Notice:</strong> Missing certificate records under TLS 1.3 do NOT imply the certificate is invalid or insecure.
        </p>
      </div>
    </div>
  );
};
