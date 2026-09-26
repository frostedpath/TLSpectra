import React from 'react';
import {
  Upload, Shield, FileText, Server, AlertTriangle,
  History, Settings as SettingsIcon, BookOpen, Layers
} from 'lucide-react';

interface SidebarNavProps {
  activeScreen: string;
  onNavigate: (screen: string) => void;
  hasActiveCapture: boolean;
}

export const SidebarNav: React.FC<SidebarNavProps> = ({ activeScreen, onNavigate, hasActiveCapture }) => {
  const mainNav = [
    { id: 'new-analysis', label: 'New Analysis', icon: Upload },
    { id: 'captures-history', label: 'Captures History', icon: History },
  ];

  const captureNav = [
    { id: 'capture-overview', label: 'Capture Overview', icon: Shield },
    { id: 'findings', label: 'Security Findings', icon: AlertTriangle },
    { id: 'sessions', label: 'Email Sessions', icon: Layers },
    { id: 'hosts', label: 'Host Inventory', icon: Server },
    { id: 'evidence-explorer', label: 'Evidence Explorer', icon: BookOpen },
    { id: 'report-builder', label: 'Report Builder', icon: FileText },
  ];

  const systemNav = [
    { id: 'policy', label: 'Assessment Policy', icon: Shield },
    { id: 'methodology', label: 'Methodology & Limits', icon: BookOpen },
    { id: 'settings', label: 'Settings', icon: SettingsIcon },
  ];

  return (
    <aside className="w-64 bg-surface border-r border-border flex flex-col h-screen shrink-0" aria-label="Main Navigation">
      {/* Brand Header */}
      <div className="p-4 border-b border-border flex items-center gap-3">
        <div className="w-8 h-8 rounded-md bg-primary text-white flex items-center justify-center font-bold text-lg shadow-sm">
          T
        </div>
        <div className="min-w-0 flex-1">
          <div className="font-bold text-sm tracking-tight text-textPrimary leading-none">TLSpectra</div>
          <div className="text-[10px] text-muted truncate mt-1" title="Evidence-Driven Cryptographic Network Forensics">Evidence-Driven Cryptographic Network Forensics</div>
        </div>
      </div>

      {/* Navigation Sections */}
      <div className="flex-1 overflow-y-auto p-3 space-y-6">
        {/* Main Workflows */}
        <div>
          <div className="px-2 text-[11px] font-semibold uppercase tracking-wider text-muted mb-1.5">Intake</div>
          <nav className="space-y-0.5">
            {mainNav.map((item) => {
              const Icon = item.icon;
              const isActive = activeScreen === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onNavigate(item.id)}
                  className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-primary text-white shadow-sm'
                      : 'text-textSecondary hover:bg-elevated hover:text-textPrimary'
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Analysis & Findings Navigation */}
        <div>
          <div className="px-2 text-[11px] font-semibold uppercase tracking-wider text-muted mb-1.5 flex items-center justify-between">
            <span>Analysis</span>
            {hasActiveCapture && (
              <span className="inline-flex items-center gap-1 text-[10px] font-normal text-semantic-success lowercase">
                <span className="w-1.5 h-1.5 rounded-full bg-semantic-success animate-pulse" />
                active
              </span>
            )}
          </div>
          <nav className="space-y-0.5">
            {captureNav.map((item) => {
              const Icon = item.icon;
              const isActive = activeScreen === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onNavigate(item.id)}
                  className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-primary text-white shadow-sm'
                      : 'text-textSecondary hover:bg-elevated hover:text-textPrimary'
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Configuration & Methodology */}
        <div>
          <div className="px-2 text-[11px] font-semibold uppercase tracking-wider text-muted mb-1.5">Configuration</div>
          <nav className="space-y-0.5">
            {systemNav.map((item) => {
              const Icon = item.icon;
              const isActive = activeScreen === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onNavigate(item.id)}
                  className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-primary text-white shadow-sm'
                      : 'text-textSecondary hover:bg-elevated hover:text-textPrimary'
                  }`}
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Security Status Footer */}
      <div className="p-3 border-t border-border bg-elevated/50 text-[11px] text-muted">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-semantic-success"></span>
          <span>Local Engine Active</span>
        </div>
      </div>
    </aside>
  );
};
