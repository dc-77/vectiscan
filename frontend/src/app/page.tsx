'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { createScan, getScanStatus, cancelScan, verifyPassword, ScanStatus } from '@/lib/api';
import VectiScanLogo from '@/components/VectiScanLogo';
import ScanProgress from '@/components/ScanProgress';
import ReportDownload from '@/components/ReportDownload';
import ScanError from '@/components/ScanError';
import PackageSelector, { ScanPackage } from '@/components/PackageSelector';
import ScanTerminal from '@/components/terminal/ScanTerminal';
import { useTerminalFeed } from '@/components/terminal/useTerminalFeed';
import { useWebSocket, WsMessage } from '@/hooks/useWebSocket';

const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export default function Home() {
  const [authenticated, setAuthenticated] = useState(false);
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [domain, setDomain] = useState('');
  const [selectedPackage, setSelectedPackage] = useState<ScanPackage>('professional');
  const [scanId, setScanId] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [showReport, setShowReport] = useState(false);
  const [terminalOpen, setTerminalOpen] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { lines, processStatus, initTerminal, reset: resetTerminal } = useTerminalFeed();

  // WebSocket message handler — updates scan state from real-time events
  const handleWsMessage = useCallback((msg: WsMessage) => {
    if (msg.type === 'connected') return;

    setScan((prev) => {
      if (!prev) return prev;
      const updated = { ...prev };

      if (msg.type === 'progress') {
        updated.status = msg.status || prev.status;
        updated.progress = {
          ...prev.progress,
          phase: msg.currentPhase ?? prev.progress.phase,
          currentTool: msg.currentTool ?? prev.progress.currentTool,
          currentHost: msg.currentHost ?? prev.progress.currentHost,
          hostsCompleted: msg.hostsCompleted ?? prev.progress.hostsCompleted,
          hostsTotal: msg.hostsTotal ?? prev.progress.hostsTotal,
          discoveredHosts: prev.progress.discoveredHosts,
        };
      } else if (msg.type === 'hosts_discovered' && msg.hosts) {
        updated.progress = {
          ...prev.progress,
          hostsTotal: msg.hostsTotal ?? prev.progress.hostsTotal,
          discoveredHosts: msg.hosts.map((h) => ({ ...h, status: 'pending' })),
        };
      } else if (msg.type === 'status') {
        updated.status = msg.status || prev.status;
      } else if (msg.type === 'error') {
        updated.status = 'failed';
        updated.error = msg.error || prev.error;
      }

      processStatus(updated);
      return updated;
    });
  }, [processStatus]);

  const handleWsConnectionChange = useCallback((connected: boolean) => {
    setWsConnected(connected);
  }, []);

  const { close: closeWs } = useWebSocket(scanId, {
    onMessage: handleWsMessage,
    onConnectionChange: handleWsConnectionChange,
  });

  useEffect(() => {
    if (sessionStorage.getItem('vectiscan_auth') === 'true') {
      setAuthenticated(true);
    }
  }, []);

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthLoading(true);
    try {
      const res = await verifyPassword(password);
      if (res.success) {
        sessionStorage.setItem('vectiscan_auth', 'true');
        setAuthenticated(true);
      } else {
        setAuthError(res.error || 'Falsches Passwort');
      }
    } catch {
      setAuthError('API nicht erreichbar.');
    } finally {
      setAuthLoading(false);
    }
  };

  const stopPolling = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  const pollStatus = useCallback(async (id: string) => {
    try {
      const res = await getScanStatus(id);
      if (res.success && res.data) {
        setScan(res.data);
        processStatus(res.data);
      }
    } catch {
      // Network error — keep polling
    }
  }, [processStatus]);

  const startPolling = useCallback((id: string) => {
    stopPolling();
    pollStatus(id);
    const interval = wsConnected ? 15000 : 3000;
    intervalRef.current = setInterval(() => pollStatus(id), interval);
  }, [pollStatus, stopPolling, wsConnected]);

  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

  // Stop polling when scan completes or fails
  useEffect(() => {
    if (!scan) return;
    if (scan.status === 'report_complete') {
      stopPolling();
      closeWs();
      setTimeout(() => setShowReport(true), 500);
    } else if (scan.status === 'failed' || scan.status === 'cancelled') {
      stopPolling();
      closeWs();
    }
  }, [scan?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setScan(null);
    setScanId(null);

    const trimmed = domain.trim().toLowerCase();
    if (!DOMAIN_REGEX.test(trimmed)) {
      setError('Ungültige Domain. Bitte einen gültigen FQDN eingeben (ohne http://, Pfad oder Port).');
      return;
    }

    setSubmitting(true);
    try {
      const res = await createScan(trimmed, selectedPackage);
      if (res.success && res.data) {
        setScanId(res.data.id);
        initTerminal(trimmed, selectedPackage);
        setShowReport(false);
        setTerminalOpen(true);
        startPolling(res.data.id);
      } else {
        setError(res.error || 'Unbekannter Fehler');
      }
    } catch {
      setError('API nicht erreichbar. Läuft der Backend-Server?');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRetry = () => {
    stopPolling();
    closeWs();
    resetTerminal();
    setShowReport(false);
    setDomain('');
    setSelectedPackage('professional');
    setScanId(null);
    setScan(null);
    setError(null);
    setCancelling(false);
  };

  const handleCancel = async () => {
    if (!scanId) return;
    setCancelling(true);
    try {
      await cancelScan(scanId);
      stopPolling();
      handleRetry();
    } catch {
      setCancelling(false);
    }
  };

  const isScanning = scanId && scan && scan.status !== 'report_complete' && scan.status !== 'failed' && scan.status !== 'cancelled';

  if (!authenticated) {
    return (
      <main className="min-h-screen flex flex-col items-center justify-center px-4 py-12">
        <div className="w-full max-w-sm space-y-6">
          <div className="text-center space-y-2">
            <VectiScanLogo className="mb-4" />
            <p className="text-gray-400">Zugang zum Security-Scanner</p>
          </div>
          <form onSubmit={handleAuth} className="space-y-4">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Passwort eingeben"
              autoFocus
              disabled={authLoading}
              className="w-full bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={authLoading || !password.trim()}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-lg transition-colors"
            >
              {authLoading ? 'Prüfe...' : 'Anmelden'}
            </button>
          </form>
          {authError && (
            <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm text-center">
              {authError}
            </div>
          )}
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-4xl space-y-6">
        {/* Header — always visible when no report shown */}
        {!showReport && (
          <div className="text-center space-y-2">
            <VectiScanLogo className="mb-4" />
            <p className="text-gray-400">Automatisierte Security-Scan-Plattform</p>
          </div>
        )}

        {/* Form — only when no scan is running */}
        {!scanId && !showReport && (
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex gap-3 max-w-2xl mx-auto">
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="beispiel.de"
                disabled={submitting}
                className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono disabled:opacity-50"
              />
              <button
                type="submit"
                disabled={submitting || !domain.trim()}
                className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-lg transition-colors"
              >
                {submitting ? 'Startet...' : 'Scan starten'}
              </button>
            </div>
            <PackageSelector selected={selectedPackage} onSelect={setSelectedPackage} />
          </form>
        )}

        {/* Error Toast */}
        {error && !scanId && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {/* Scan in progress: Professional status card + terminal box */}
        {scan && scan.status !== 'report_complete' && scan.status !== 'cancelled' && (
          <>
            {/* Primary: ScanProgress with progress bar and status */}
            <ScanProgress
              scan={scan}
              onCancel={isScanning ? handleCancel : undefined}
              cancelling={cancelling}
            />

            {/* Secondary: Collapsible terminal log */}
            <div className="rounded-lg border border-[#1E3A5F]/50 overflow-hidden">
              <button
                onClick={() => setTerminalOpen(!terminalOpen)}
                className="w-full flex items-center justify-between px-4 py-2.5 bg-[#0C1222] hover:bg-[#0F172A] transition-colors"
              >
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${isScanning ? 'bg-[#38BDF8] animate-pulse' : scan.status === 'failed' ? 'bg-red-500' : 'bg-[#4B7399]'}`} />
                  <span className="text-xs font-mono text-[#4B7399]">Terminal Log</span>
                  <span className="text-xs text-[#1E3A5F] font-mono">{lines.length} lines</span>
                </div>
                <span className="text-[#4B7399] text-xs">
                  {terminalOpen ? '▲ Einklappen' : '▼ Aufklappen'}
                </span>
              </button>

              {terminalOpen && (
                <ScanTerminal
                  lines={lines}
                  currentTool={scan.progress.currentTool || null}
                  currentHost={scan.progress.currentHost || null}
                  isScanning={!!isScanning}
                  isComplete={scan.status === 'report_complete'}
                  isError={scan.status === 'failed'}
                  compact
                />
              )}
            </div>
          </>
        )}

        {/* Report download */}
        {showReport && scan?.status === 'report_complete' && (
          <div className="animate-fadeIn">
            <ReportDownload
              scanId={scan.id}
              domain={scan.domain}
              onNewScan={handleRetry}
            />
          </div>
        )}

        {/* Error or cancelled — with retry button */}
        {(scan?.status === 'failed' || scan?.status === 'cancelled') && (
          <ScanError error={scan.error} onRetry={handleRetry} />
        )}
      </div>
    </main>
  );
}
