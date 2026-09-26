import React, { useState } from 'react';
import { Settings as SettingsIcon, Key, Eye, EyeOff, Trash2, CheckCircle2, Shield } from 'lucide-react';

export const Settings: React.FC = () => {
  const [token, setToken] = useState<string>(localStorage.getItem('sms_bearer_token') || 'sms_sec_token_v1');
  const [showToken, setShowToken] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSaveToken = (e: React.FormEvent) => {
    e.preventDefault();
    localStorage.setItem('sms_bearer_token', token);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleClearData = () => {
    if (window.confirm('Clear all locally cached assessment state and tokens?')) {
      localStorage.clear();
      window.location.reload();
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-textPrimary tracking-tight">System Settings</h2>
        <p className="text-xs text-muted">
          Authentication credentials, local privacy configuration, and storage controls.
        </p>
      </div>

      {/* Bearer Token Config */}
      <form onSubmit={handleSaveToken} className="bg-surface border border-border rounded-lg p-6 shadow-sm space-y-4 text-xs">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-2 font-bold text-textPrimary text-sm">
            <Key className="w-4 h-4 text-primary" />
            <span>Static Bearer Token Authentication</span>
          </div>
          {saved && (
            <span className="flex items-center gap-1 text-[11px] text-semantic-success font-semibold">
              <CheckCircle2 className="w-3.5 h-3.5" /> Token Saved
            </span>
          )}
        </div>

        <div className="space-y-1.5">
          <label className="font-semibold text-textPrimary">Authorization Bearer Token</label>
          <div className="relative flex items-center">
            <input
              type={showToken ? 'text' : 'password'}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="w-full bg-background border border-border rounded-md pl-3 pr-10 py-2 font-mono text-xs text-textPrimary"
            />
            <button
              type="button"
              onClick={() => setShowToken(!showToken)}
              className="absolute right-3 text-muted hover:text-textPrimary"
            >
              {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          <p className="text-[11px] text-muted">
            Static bearer token used to authenticate requests to the local backend API.
          </p>
        </div>

        <div className="flex justify-end pt-2">
          <button
            type="submit"
            className="px-4 py-2 bg-primary hover:bg-primary-hover text-white font-semibold rounded-md transition-colors"
          >
            Update Token
          </button>
        </div>
      </form>

      {/* Privacy & Retention Cleanup */}
      <div className="bg-surface border border-border rounded-lg p-6 shadow-sm space-y-4 text-xs">
        <div className="flex items-center gap-2 font-bold text-textPrimary text-sm border-b border-border pb-3">
          <Shield className="w-4 h-4 text-secondary" />
          <span>Local Storage & Retention Controls</span>
        </div>

        <p className="text-textSecondary leading-relaxed">
          TLSpectra stores forensic metadata locally. You can purge cached data from your browser session at any time.
        </p>

        <div>
          <button
            onClick={handleClearData}
            className="flex items-center gap-1.5 px-3 py-2 bg-red-50 hover:bg-red-100 border border-red-200 text-semantic-error font-semibold rounded-md transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            <span>Purge Local Browser Session Data</span>
          </button>
        </div>
      </div>
    </div>
  );
};
