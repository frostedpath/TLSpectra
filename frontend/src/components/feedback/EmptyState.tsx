import React from 'react';
import { LucideIcon, Inbox } from 'lucide-react';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon = Inbox,
  title,
  description,
  actionLabel,
  onAction
}) => {
  return (
    <div className="bg-surface border border-border rounded-xl p-12 text-center flex flex-col items-center justify-center shadow-sm">
      <div className="w-12 h-12 rounded-full bg-background border border-border text-muted flex items-center justify-center mb-3">
        <Icon className="w-6 h-6" />
      </div>
      <h3 className="text-sm font-semibold text-textPrimary">{title}</h3>
      <p className="text-xs text-muted max-w-sm mt-1 mb-4 leading-relaxed">{description}</p>
      {actionLabel && onAction && (
        <button
          onClick={onAction}
          className="px-4 py-2 bg-primary hover:bg-primary-hover text-white text-xs font-semibold rounded-md shadow-sm transition-colors"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
};
