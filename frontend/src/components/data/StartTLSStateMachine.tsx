import React from 'react';
import { ArrowRight, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

interface StartTLSStateMachineProps {
  state: string;
}

export const StartTLSStateMachine: React.FC<StartTLSStateMachineProps> = ({ state }) => {
  const steps = [
    { id: 'OFFERED', label: '1. 250-STARTTLS Offered' },
    { id: 'REQUESTED', label: '2. STARTTLS Requested' },
    { id: 'ACCEPTED', label: '3. 220 Ready / Accepted' },
    { id: 'TLS_ESTABLISHED', label: '4. TLS Handshake' },
  ];

  const getStateInfo = () => {
    switch (state) {
      case 'TLS_ESTABLISHED':
        return { color: 'text-semantic-success', bg: 'bg-emerald-50 border-emerald-200', text: 'Secure TLS Established' };
      case 'CLEARTEXT_AFTER_OFFER':
        return { color: 'text-semantic-error', bg: 'bg-red-50 border-red-200', text: 'STARTTLS Offered but Ignored (Cleartext Traffic)' };
      case 'REJECTED':
      case 'FAILED':
        return { color: 'text-semantic-error', bg: 'bg-red-50 border-red-200', text: 'STARTTLS Negotiation Failed / Error' };
      case 'NOT_OFFERED':
        return { color: 'text-textSecondary', bg: 'bg-slate-50 border-slate-200', text: 'STARTTLS Not Advertised' };
      default:
        return { color: 'text-primary', bg: 'bg-blue-50 border-blue-200', text: state };
    }
  };

  const status = getStateInfo();

  return (
    <div className="bg-surface border border-border rounded-lg p-5 shadow-sm space-y-4">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <h3 className="text-sm font-semibold text-textPrimary">STARTTLS / STLS State Machine</h3>
        <span className={`px-2.5 py-1 rounded text-xs font-semibold border ${status.bg} ${status.color}`}>
          {status.text}
        </span>
      </div>

      {/* Visual Sequence */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 pt-2">
        {steps.map((step, idx) => {
          const isComplete =
            (state === 'TLS_ESTABLISHED' && idx <= 3) ||
            (state === 'ACCEPTED' && idx <= 2) ||
            (state === 'REQUESTED' && idx <= 1) ||
            (state === 'OFFERED' && idx === 0);

          const isFailed =
            (state === 'CLEARTEXT_AFTER_OFFER' && idx === 1) ||
            ((state === 'REJECTED' || state === 'FAILED') && idx === 2);

          return (
            <div
              key={step.id}
              className={`p-3 rounded-md border text-xs flex flex-col justify-between ${
                isComplete
                  ? 'bg-emerald-50/50 border-emerald-300 text-emerald-800'
                  : isFailed
                  ? 'bg-red-50/50 border-red-300 text-red-800'
                  : 'bg-background border-border text-muted'
              }`}
            >
              <div className="font-medium">{step.label}</div>
              <div className="mt-2 flex items-center justify-end">
                {isComplete ? (
                  <CheckCircle className="w-4 h-4 text-secondary" />
                ) : isFailed ? (
                  <XCircle className="w-4 h-4 text-semantic-error" />
                ) : (
                  <span className="w-2 h-2 rounded-full bg-slate-200" />
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
