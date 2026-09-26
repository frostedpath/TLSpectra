import React from 'react';
import { X, Keyboard } from 'lucide-react';

interface KeyboardShortcutHelpProps {
  isOpen: boolean;
  onClose: () => void;
}

export const KeyboardShortcutHelp: React.FC<KeyboardShortcutHelpProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  const shortcuts = [
    { key: '?', desc: 'Open keyboard shortcuts help' },
    { key: '⌘ + K / Ctrl + K', desc: 'Global search findings & sessions' },
    { key: 'Esc', desc: 'Close open drawers, dialogs & modals' },
    { key: 'Tab / Shift+Tab', desc: 'Navigate between interactive controls' },
    { key: 'Enter / Space', desc: 'Select finding / activate row detail' },
    { key: 'N', desc: 'Navigate to New Analysis / Upload' },
    { key: 'O', desc: 'Navigate to Capture Overview' },
    { key: 'F', desc: 'Navigate to Security Findings list' },
  ];

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4 animate-in fade-in duration-150">
      <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 shadow-L3 space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2 font-bold text-textPrimary text-sm">
            <Keyboard className="w-4 h-4 text-primary" />
            <span>Keyboard Navigation Shortcuts</span>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-muted hover:text-textPrimary rounded hover:bg-elevated transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="divide-y divide-border text-xs">
          {shortcuts.map((s, idx) => (
            <div key={idx} className="py-2.5 flex items-center justify-between">
              <span className="text-textSecondary">{s.desc}</span>
              <kbd className="px-2 py-1 bg-background border border-border rounded font-mono text-[11px] text-textPrimary font-semibold">
                {s.key}
              </kbd>
            </div>
          ))}
        </div>

        <div className="pt-2 text-[11px] text-muted text-center">
          TLSpectra supports standard WCAG 2.1 keyboard navigation throughout.
        </div>
      </div>
    </div>
  );
};
