import React, { useState, useEffect } from 'react';
import { SidebarNav } from './SidebarNav';
import { TopBar } from './TopBar';
import { CaptureContextBar } from './CaptureContextBar';
import { SkipToContent } from '../a11y/SkipToContent';
import { KeyboardShortcutHelp } from '../a11y/KeyboardShortcutHelp';
import { Capture, ScoreData } from '../../types';
import { SearchInput } from '../forms/SearchInput';
import { X, Layers, AlertTriangle, Server, Shield } from 'lucide-react';

interface AppShellProps {
  activeScreen: string;
  onNavigate: (screen: string) => void;
  activeCapture: Capture | null;
  activeScore?: ScoreData;
  onClearCapture: () => void;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  activeScreen,
  onNavigate,
  activeCapture,
  activeScore,
  onClearCapture,
  children
}) => {
  const [isHelpOpen, setIsHelpOpen] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const onNavigateRef = React.useRef(onNavigate);
  useEffect(() => {
    onNavigateRef.current = onNavigate;
  }, [onNavigate]);

  // Global keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const isInput = Boolean(
        target && (
          ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) ||
          target.isContentEditable
        )
      );

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsSearchOpen(true);
        return;
      }

      if (e.key === 'Escape') {
        setIsHelpOpen(false);
        setIsSearchOpen(false);
        return;
      }

      // Ignore single-key shortcuts while typing in editable elements
      if (isInput) return;

      if (e.key === '?') {
        e.preventDefault();
        setIsHelpOpen((prev) => !prev);
        return;
      }

      // Single-letter shortcuts (N: New Analysis, O: Capture Overview, F: Findings)
      if (!e.ctrlKey && !e.metaKey && !e.altKey) {
        const key = e.key.toLowerCase();
        if (key === 'n') {
          e.preventDefault();
          setIsHelpOpen(false);
          setIsSearchOpen(false);
          onNavigateRef.current('new-analysis');
        } else if (key === 'o') {
          e.preventDefault();
          setIsHelpOpen(false);
          setIsSearchOpen(false);
          onNavigateRef.current('capture-overview');
        } else if (key === 'f') {
          e.preventDefault();
          setIsHelpOpen(false);
          setIsSearchOpen(false);
          onNavigateRef.current('findings');
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const getScreenTitle = () => {
    const titles: Record<string, string> = {
      'new-analysis': 'New Analysis / Capture Intake',
      'processing': 'Capture Processing',
      'captures-history': 'Historical Captures Repository',
      'capture-overview': 'Cryptographic Security Posture Overview',
      'findings': 'Security Findings & Rule Detections',
      'sessions': 'Reconstructed Email Sessions',
      'hosts': 'Observed Mail Hosts Inventory',
      'evidence-explorer': 'Passive Evidence Explorer',
      'report-builder': 'Executive & Compliance Report Builder',
      'policy': 'Assessment Policy Configuration',
      'methodology': 'Methodology, Standards & Visibility Limits',
      'settings': 'System Settings & Token Management',
    };
    return titles[activeScreen] || 'Security Workstation';
  };

  return (
    <div className="flex h-screen bg-background overflow-hidden selection:bg-primary/20 selection:text-primary">
      <SkipToContent />

      {/* Main Sidebar Navigation */}
      <SidebarNav
        activeScreen={activeScreen}
        onNavigate={onNavigate}
        hasActiveCapture={Boolean(activeCapture)}
      />

      {/* Workspace Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <TopBar
          activeScreenTitle={getScreenTitle()}
          onSearchClick={() => setIsSearchOpen(true)}
          onHelpClick={() => setIsHelpOpen(true)}
        />

        {/* Capture Context Bar */}
        {activeCapture && activeScreen !== 'new-analysis' && activeScreen !== 'processing' && (
          <CaptureContextBar
            capture={activeCapture}
            score={activeScore}
            onClearCapture={onClearCapture}
          />
        )}

        {/* Main Content Container */}
        <main
          id="main-content"
          tabIndex={-1}
          className="flex-1 overflow-y-auto p-6 space-y-6 focus:outline-none"
        >
          {children}
        </main>
      </div>

      {/* Keyboard Shortcut Help Dialog */}
      <KeyboardShortcutHelp
        isOpen={isHelpOpen}
        onClose={() => setIsHelpOpen(false)}
      />

      {/* Global Quick Search Overlay */}
      {isSearchOpen && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-start justify-center pt-20 p-4 animate-in fade-in duration-150">
          <div className="bg-surface border border-border rounded-xl max-w-lg w-full p-4 shadow-L3 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-muted uppercase tracking-wider">Quick Search Navigator</span>
              <button
                onClick={() => setIsSearchOpen(false)}
                className="p-1 text-muted hover:text-textPrimary rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <SearchInput
              value={searchQuery}
              onChange={setSearchQuery}
              placeholder="Search findings (e.g. TLS-001), sessions, or hosts..."
            />

            <div className="space-y-1 text-xs pt-1 max-h-60 overflow-y-auto">
              <div className="p-2 text-[11px] font-semibold text-muted uppercase">Direct Jump</div>
              <button
                onClick={() => { onNavigate('findings'); setIsSearchOpen(false); }}
                className="w-full text-left p-2 hover:bg-elevated rounded flex items-center gap-2 text-textPrimary"
              >
                <AlertTriangle className="w-4 h-4 text-semantic-warning" />
                <span>Security Findings Repository</span>
              </button>
              <button
                onClick={() => { onNavigate('sessions'); setIsSearchOpen(false); }}
                className="w-full text-left p-2 hover:bg-elevated rounded flex items-center gap-2 text-textPrimary"
              >
                <Layers className="w-4 h-4 text-primary" />
                <span>Reconstructed Sessions</span>
              </button>
              <button
                onClick={() => { onNavigate('hosts'); setIsSearchOpen(false); }}
                className="w-full text-left p-2 hover:bg-elevated rounded flex items-center gap-2 text-textPrimary"
              >
                <Server className="w-4 h-4 text-secondary" />
                <span>Host Inventory</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
