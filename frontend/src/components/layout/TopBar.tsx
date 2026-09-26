import React from 'react';
import { Search, HelpCircle, Bell, ShieldCheck } from 'lucide-react';

interface TopBarProps {
  onSearchClick: () => void;
  onHelpClick: () => void;
  activeScreenTitle: string;
}

export const TopBar: React.FC<TopBarProps> = ({ onSearchClick, onHelpClick, activeScreenTitle }) => {
  return (
    <header className="h-14 bg-surface border-b border-border flex items-center justify-between px-6 shrink-0">
      <div className="flex items-center gap-3">
        <h1 className="text-sm font-semibold text-textPrimary tracking-tight">{activeScreenTitle}</h1>
      </div>

      <div className="flex items-center gap-2">
        {/* Quick Search Shortcut */}
        <button
          onClick={onSearchClick}
          className="flex items-center gap-2 px-3 py-1.5 text-xs text-muted bg-background hover:bg-elevated border border-border rounded-md transition-colors"
          title="Search findings, sessions, hosts (Ctrl+K)"
        >
          <Search className="w-3.5 h-3.5" />
          <span>Search...</span>
          <kbd className="text-[10px] bg-surface px-1.5 py-0.5 border border-border rounded font-mono">⌘K</kbd>
        </button>

        {/* Engine Health Indicator */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] text-semantic-success bg-semantic-success/10 border border-semantic-success/20 rounded-md">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span className="font-medium">API Ready</span>
        </div>

        {/* Keyboard Help */}
        <button
          onClick={onHelpClick}
          className="p-2 text-muted hover:text-textPrimary hover:bg-elevated rounded-md transition-colors"
          title="Keyboard shortcuts & Help (?)"
        >
          <HelpCircle className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
