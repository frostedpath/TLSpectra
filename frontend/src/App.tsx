import React, { useState, useEffect } from 'react';
import { AppShell } from './components/layout/AppShell';
import { NewAnalysis } from './pages/NewAnalysis';
import { Processing } from './pages/Processing';
import { CapturesHistory } from './pages/CapturesHistory';
import { CaptureOverview } from './pages/CaptureOverview';
import { Findings } from './pages/Findings';
import { Sessions } from './pages/Sessions';
import { Hosts } from './pages/Hosts';
import { EvidenceExplorer } from './pages/EvidenceExplorer';
import { ReportBuilder } from './pages/ReportBuilder';
import { PolicyEditor } from './pages/Policy';
import { Methodology } from './pages/Methodology';
import { Settings } from './pages/Settings';
import { Capture, ScoreData } from './types';
import { api } from './api/client';
import { Layers } from 'lucide-react';

export function App() {
  const [activeScreen, setActiveScreen] = useState<string>('new-analysis');
  const [activeCapture, setActiveCapture] = useState<Capture | null>(null);
  const [activeScore, setActiveScore] = useState<ScoreData | undefined>(undefined);
  const [recentCaptures, setRecentCaptures] = useState<Capture[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);

  const loadRecent = async () => {
    try {
      const res = await api.listCaptures(10);
      setRecentCaptures(res.items);
      if (res.items.length > 0 && !activeCapture) {
        // Default to latest completed capture if available
        const completed = res.items.find((c) => c.status === 'COMPLETE');
        if (completed) {
          selectCapture(completed);
        }
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadRecent();
  }, [activeScreen]);

  const selectCapture = async (cap: Capture) => {
    try {
      const freshCap = await api.getCapture(cap.capture_id);
      setActiveCapture(freshCap);
      if (freshCap.status === 'COMPLETE') {
        const score = await api.getCaptureScore(freshCap.capture_id);
        setActiveScore(score);
      } else {
        setActiveScore(undefined);
      }
    } catch (e) {
      setActiveCapture(cap);
      setActiveScore(undefined);
    }
  };

  const handleCaptureCreated = (newCap: Capture) => {
    setActiveCapture(newCap);
    setActiveScore(undefined);
    setActiveScreen('processing');
    setRecentCaptures((prev) => [newCap, ...prev]);
  };

  const handleProcessingComplete = async (completedCap: Capture) => {
    await selectCapture(completedCap);
    await loadRecent();
    setActiveScreen('capture-overview');
  };

  const handleProcessingFailed = (errorMsg: string) => {
    alert(`Capture analysis failed: ${errorMsg}`);
    setActiveScreen('new-analysis');
  };

  const handleClearCapture = () => {
    setActiveScreen('new-analysis');
  };

  const handleDrillToSession = (sessionId: string) => {
    setSelectedSessionId(sessionId);
    setActiveScreen('sessions');
  };

  const handleNavigate = (screen: string) => {
    setSelectedSessionId(null);
    const analysisScreens = [
      'capture-overview',
      'findings',
      'sessions',
      'hosts',
      'evidence-explorer',
      'report-builder'
    ];
    if (analysisScreens.includes(screen) && !activeCapture && recentCaptures.length > 0) {
      const completed = recentCaptures.find((c) => c.status === 'COMPLETE') || recentCaptures[0];
      if (completed) {
        selectCapture(completed);
      }
    }
    setActiveScreen(screen);
  };

  return (
    <AppShell
      activeScreen={activeScreen}
      onNavigate={handleNavigate}
      activeCapture={activeCapture}
      activeScore={activeScore}
      onClearCapture={handleClearCapture}
    >
      {activeScreen === 'new-analysis' && (
        <NewAnalysis
          onCaptureCreated={handleCaptureCreated}
          onSelectExistingCapture={(cap) => {
            selectCapture(cap);
            setActiveScreen('capture-overview');
          }}
          recentCaptures={recentCaptures}
        />
      )}

      {activeScreen === 'processing' && activeCapture && (
        <Processing
          capture={activeCapture}
          onProcessingComplete={handleProcessingComplete}
          onProcessingFailed={handleProcessingFailed}
        />
      )}

      {activeScreen === 'captures-history' && (
        <CapturesHistory
          onSelectCapture={(cap) => {
            selectCapture(cap);
            setActiveScreen('capture-overview');
          }}
          onNavigateToUpload={() => setActiveScreen('new-analysis')}
        />
      )}

      {['capture-overview', 'findings', 'sessions', 'hosts', 'evidence-explorer', 'report-builder'].includes(activeScreen) && !activeCapture && (
        <div className="flex flex-col items-center justify-center p-12 text-center bg-surface border border-border rounded-xl max-w-md mx-auto my-12 shadow-sm">
          <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center text-primary mb-4">
            <Layers className="w-6 h-6" />
          </div>
          <h3 className="text-base font-semibold text-textPrimary">No Active Capture Selected</h3>
          <p className="text-xs text-muted max-w-sm mt-1 mb-5 leading-relaxed">
            Select an analyzed capture from your history or upload an email PCAP capture to view security posture, findings, and reconstructed sessions.
          </p>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setActiveScreen('new-analysis')}
              className="px-4 py-2 text-xs font-medium rounded-md bg-primary text-white hover:bg-primary/90 transition-colors shadow-sm"
            >
              Upload New PCAP
            </button>
            <button
              onClick={() => setActiveScreen('captures-history')}
              className="px-4 py-2 text-xs font-medium rounded-md border border-border bg-surface text-textSecondary hover:bg-elevated hover:text-textPrimary transition-colors"
            >
              Captures History
            </button>
          </div>
        </div>
      )}

      {activeScreen === 'capture-overview' && activeCapture && (
        <CaptureOverview
          capture={activeCapture}
          onNavigate={(screen) => setActiveScreen(screen)}
          onSelectSession={handleDrillToSession}
        />
      )}

      {activeScreen === 'findings' && activeCapture && (
        <Findings
          capture={activeCapture}
          onSelectSession={handleDrillToSession}
        />
      )}

      {activeScreen === 'sessions' && activeCapture && (
        <Sessions
          capture={activeCapture}
          selectedSessionId={selectedSessionId}
          onClearSelectedSession={() => setSelectedSessionId(null)}
        />
      )}

      {activeScreen === 'hosts' && activeCapture && (
        <Hosts capture={activeCapture} />
      )}

      {activeScreen === 'evidence-explorer' && activeCapture && (
        <EvidenceExplorer capture={activeCapture} />
      )}

      {activeScreen === 'report-builder' && activeCapture && (
        <ReportBuilder capture={activeCapture} />
      )}

      {activeScreen === 'policy' && <PolicyEditor />}

      {activeScreen === 'methodology' && <Methodology />}

      {activeScreen === 'settings' && <Settings />}
    </AppShell>
  );
}
