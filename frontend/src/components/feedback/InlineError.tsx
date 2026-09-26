import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface InlineErrorProps {
  message: string;
  onRetry?: () => void;
  className?: string;
}

export const InlineError: React.FC<InlineErrorProps> = ({ message, onRetry, className = '' }) => {
  return (
    <div className={`p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3 text-xs text-semantic-error ${className}`}>
      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
      <div className="flex-1">
        <div className="font-semibold">Error Encountered</div>
        <p className="mt-0.5 text-red-700">{message}</p>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-1.5 px-3 py-1 bg-white border border-red-300 rounded text-red-700 hover:bg-red-50 font-medium transition-colors"
        >
          <RefreshCw className="w-3 h-3" />
          <span>Retry</span>
        </button>
      )}
    </div>
  );
};
