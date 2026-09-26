import React from 'react';
import { BookOpen, Shield, Eye, Layers } from 'lucide-react';

export const Methodology: React.FC = () => {
  const standards = [
    { code: 'RFC 8446', title: 'The Transport Layer Security (TLS) Protocol Version 1.3', note: 'Defines modern TLS 1.3 protocol and encrypted handshake specifications.' },
    { code: 'RFC 8996', title: 'Deprecating TLS 1.0 and TLS 1.1', note: 'Formal deprecation of legacy TLS versions vulnerable to protocol attacks.' },
    { code: 'RFC 8314', title: 'Cleartext Replacement in Email Protocols', note: 'Mandates TLS for email submission and retrieval, discouraging cleartext auth.' },
    { code: 'RFC 3207', title: 'SMTP Service Extension for Secure SMTP over Transport Layer Security', note: 'STARTTLS state machine specifications and error handling.' },
    { code: 'RFC 6125', title: 'Service Identity Verification (SAN / CN matching)', note: 'Strict identity verification rules between observed SNI and X.509 SAN entries.' },
    { code: 'RFC 5280', title: 'X.509 PKI Certificate and CRL Profile', note: 'Certificate validity, key usage, basic constraints, and chain structure.' },
    { code: 'NIST SP 800-52 Rev. 2', title: 'Guidelines for TLS Implementations', note: 'Cipher suite selection and forward secrecy recommendations.' }
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-textPrimary tracking-tight">Methodology, Standards & Visibility</h2>
        <p className="text-xs text-muted">
          Technical specifications, RFC grounding, and passive capture constraints governing TLSpectra.
        </p>
      </div>

      {/* Core Design Axioms */}
      <div className="bg-surface border border-border rounded-lg p-6 shadow-sm space-y-4 text-xs">
        <h3 className="text-sm font-bold text-textPrimary flex items-center gap-2">
          <Shield className="w-4 h-4 text-primary" />
          <span>Core Assessment Principles</span>
        </h3>
        <ul className="list-disc pl-5 space-y-2 text-textSecondary leading-relaxed">
          <li><strong>Passive & Offline-First:</strong> Assessments rely strictly on recorded packet artifacts. No active network probes or external trust verification occur without explicit configuration.</li>
          <li><strong>Evidence Before Opinion:</strong> Security claims must link to observable byte offsets or protocol transitions. A high-risk finding cannot exist without traceable evidence.</li>
          <li><strong>NOT OBSERVED ≠ OBSERVED TO BE ABSENT:</strong> Incomplete capture frames or encrypted TLS 1.3 payloads do not prove a server feature is defective.</li>
        </ul>
      </div>

      {/* Authoritative Standards */}
      <div className="bg-surface border border-border rounded-lg p-6 shadow-sm space-y-4 text-xs">
        <h3 className="text-sm font-bold text-textPrimary flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-secondary" />
          <span>Authoritative Standards References</span>
        </h3>
        <div className="divide-y divide-border">
          {standards.map((s, idx) => (
            <div key={idx} className="py-3 space-y-1">
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-textPrimary text-xs">{s.code}</span>
                <span className="text-muted">•</span>
                <span className="font-medium text-textPrimary">{s.title}</span>
              </div>
              <p className="text-textSecondary">{s.note}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Score Calibration Disclaimer */}
      <div className="p-4 bg-elevated border border-border rounded-lg text-xs text-muted italic leading-relaxed">
        <strong>Scoring Disclaimer:</strong> Posture scoring weights (0–100) are documented design decisions calibrated against the synthetic test corpus, not an industry-standard formula.
      </div>
    </div>
  );
};
