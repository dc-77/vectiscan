'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { createScan, getScanStatus, cancelScan, verifyPassword, ScanStatus } from '@/lib/api';
import VectiScanLogo from '@/components/VectiScanLogo';
import ScanProgress from '@/components/ScanProgress';
import HostList from '@/components/HostList';
import ReportDownload from '@/components/ReportDownload';
import ScanError from '@/components/ScanError';

const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export default function Home() {
  const [authenticated, setAuthenticated] = useState(false);
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [domain, setDomain] = useState('');
  const [scanId, setScanId] = useState<string | null>(null);
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

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
        if (res.data.status === 'report_complete' || res.data.status === 'failed') {
          stopPolling();
        }
      }
    } catch {
      // Network error — keep polling
    }
  }, [stopPolling]);

  const startPolling = useCallback((id: string) => {
    stopPolling();
    pollStatus(id);
    intervalRef.current = setInterval(() => pollStatus(id), 3000);
  }, [pollStatus, stopPolling]);

  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

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
      const res = await createScan(trimmed);
      if (res.success && res.data) {
        setScanId(res.data.id);
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
    setDomain('');
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

  const isScanning = scanId && scan && scan.status !== 'report_complete' && scan.status !== 'failed';

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
    <main className="min-h-screen flex flex-col items-center px-4 py-12">
      <div className="w-full max-w-2xl space-y-8">
        {/* Header */}
        <div className="text-center space-y-2">
          <VectiScanLogo className="mb-4" />
          <p className="text-gray-400">Automatisierte Security-Scan-Plattform</p>
        </div>

        {/* Domain Input Form */}
        {!scanId && (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex gap-3">
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
          </form>
        )}

        {/* Error Toast */}
        {error && !scanId && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {/* Scan Progress */}
        {scan && isScanning && (
          <ScanProgress
            scan={scan}
            onCancel={handleCancel}
            cancelling={cancelling}
          />
        )}

        {/* Host List */}
        {scan && scan.progress.discoveredHosts.length > 0 && scan.status !== 'failed' && (
          <HostList hosts={scan.progress.discoveredHosts} />
        )}

        {/* Report Download */}
        {scan && scan.status === 'report_complete' && scanId && (
          <ReportDownload scanId={scanId} onNewScan={handleRetry} />
        )}

        {/* Error State */}
        {scan && scan.status === 'failed' && (
          <ScanError error={scan.error} onRetry={handleRetry} />
        )}
      </div>
    </main>
  );
}
