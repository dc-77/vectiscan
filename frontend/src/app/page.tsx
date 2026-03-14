'use client';

import { useState, useEffect, useCallback, useRef, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { createOrder, getOrderStatus, cancelOrder, verifyPassword, OrderStatus } from '@/lib/api';
import Link from 'next/link';
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
  return (
    <Suspense>
      <HomeContent />
    </Suspense>
  );
}

function HomeContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [authenticated, setAuthenticated] = useState(false);
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [email, setEmail] = useState('');
  const [domain, setDomain] = useState('');
  const [selectedPackage, setSelectedPackage] = useState<ScanPackage>('professional');
  const [orderId, setOrderId] = useState<string | null>(null);
  const [order, setOrder] = useState<OrderStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [showReport, setShowReport] = useState(false);
  const [terminalOpen, setTerminalOpen] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { lines, processStatus, initTerminal, reset: resetTerminal } = useTerminalFeed();

  // WebSocket message handler — updates order state from real-time events
  const handleWsMessage = useCallback((msg: WsMessage) => {
    if (msg.type === 'connected') return;

    setOrder((prev) => {
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

  const { close: closeWs } = useWebSocket(orderId, {
    onMessage: handleWsMessage,
    onConnectionChange: handleWsConnectionChange,
  });

  useEffect(() => {
    if (sessionStorage.getItem('vectiscan_auth') === 'true') {
      setAuthenticated(true);
    }
  }, []);

  // Resume scan from orderId query param (from dashboard or verify redirect)
  useEffect(() => {
    const paramOrderId = searchParams.get('orderId');
    if (paramOrderId && !orderId && authenticated) {
      setOrderId(paramOrderId);
      startPolling(paramOrderId);
    }
  }, [searchParams, authenticated]); // eslint-disable-line react-hooks/exhaustive-deps

  // Redirect to verify page if order still needs verification
  // Skip redirect briefly after arriving from verify page to avoid race condition
  const fromVerifyRef = useRef(false);
  useEffect(() => {
    if (searchParams.get('orderId')) {
      fromVerifyRef.current = true;
      const timer = setTimeout(() => { fromVerifyRef.current = false; }, 10000);
      return () => clearTimeout(timer);
    }
  }, [searchParams]);

  useEffect(() => {
    if (order && orderId && !fromVerifyRef.current && (order.status === 'verification_pending' || order.status === 'verified')) {
      stopPolling();
      router.replace(`/verify/${orderId}`);
    }
  }, [order?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  // Initialize terminal once order data is available (from polling)
  useEffect(() => {
    if (order && orderId && !showReport && order.status !== 'verification_pending' && order.status !== 'verified') {
      initTerminal(order.domain, order.package);
    }
  }, [order?.domain, order?.package]); // eslint-disable-line react-hooks/exhaustive-deps

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
      const res = await getOrderStatus(id);
      if (res.success && res.data) {
        setOrder(res.data);
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

  // Stop polling when order completes or fails
  useEffect(() => {
    if (!order) return;
    if (order.status === 'report_complete') {
      stopPolling();
      closeWs();
      setTimeout(() => setShowReport(true), 500);
    } else if (order.status === 'failed' || order.status === 'cancelled') {
      stopPolling();
      closeWs();
    }
  }, [order?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setOrder(null);
    setOrderId(null);

    if (!email.trim()) {
      setError('Bitte eine E-Mail-Adresse eingeben.');
      return;
    }

    // Strip protocol, path, port, trailing slash from input
    let trimmed = domain.trim().toLowerCase()
      .replace(/^https?:\/\//, '')  // remove http:// or https://
      .replace(/\/.*$/, '')          // remove path
      .replace(/:\d+$/, '')          // remove port
      .replace(/\.$/, '');           // remove trailing dot

    if (!DOMAIN_REGEX.test(trimmed)) {
      setError('Ungültige Domain. Beispiel: beispiel.de');
      return;
    }

    setSubmitting(true);
    try {
      const res = await createOrder(email.trim(), trimmed, selectedPackage);
      if (res.success && res.data) {
        router.push(`/verify/${res.data.id}`);
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
    setEmail('');
    setDomain('');
    setSelectedPackage('professional');
    setOrderId(null);
    setOrder(null);
    setError(null);
    setCancelling(false);
  };

  const handleCancel = async () => {
    if (!orderId) return;
    setCancelling(true);
    try {
      await cancelOrder(orderId);
      stopPolling();
      handleRetry();
    } catch {
      setCancelling(false);
    }
  };

  const isScanning = orderId && order && order.status !== 'report_complete' && order.status !== 'failed' && order.status !== 'cancelled';

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
            <Link
              href="/dashboard"
              className="inline-block bg-[#1e293b] hover:bg-[#253347] text-gray-300 hover:text-white text-sm font-medium px-4 py-2 rounded-lg border border-gray-700 transition-colors mt-2"
            >
              Dashboard
            </Link>
          </div>
        )}

        {/* Form — only when no order is running */}
        {!orderId && !showReport && (
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex flex-col gap-3 max-w-2xl mx-auto">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="ihre@email.de"
                disabled={submitting}
                className="w-full bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:opacity-50"
              />
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
                  disabled={submitting || !domain.trim() || !email.trim()}
                  className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-lg transition-colors"
                >
                  {submitting ? 'Startet...' : 'Scan starten'}
                </button>
              </div>
            </div>
            <PackageSelector selected={selectedPackage} onSelect={setSelectedPackage} />
          </form>
        )}

        {/* Error Toast */}
        {error && !orderId && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {/* Scan in progress: Professional status card + terminal box */}
        {order && order.status !== 'report_complete' && order.status !== 'cancelled' && (
          <>
            {/* Primary: ScanProgress with progress bar and status */}
            <ScanProgress
              scan={order}
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
                  <span className={`w-2 h-2 rounded-full ${isScanning ? 'bg-[#38BDF8] animate-pulse' : order.status === 'failed' ? 'bg-red-500' : 'bg-[#4B7399]'}`} />
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
                  currentTool={order.progress.currentTool || null}
                  currentHost={order.progress.currentHost || null}
                  isScanning={!!isScanning}
                  isComplete={order.status === 'report_complete'}
                  isError={order.status === 'failed'}
                  compact
                />
              )}
            </div>
          </>
        )}

        {/* Report download */}
        {showReport && order?.status === 'report_complete' && (
          <div className="animate-fadeIn">
            <ReportDownload
              orderId={order.id}
              domain={order.domain}
              onNewScan={handleRetry}
            />
          </div>
        )}

        {/* Error or cancelled — with retry button */}
        {(order?.status === 'failed' || order?.status === 'cancelled') && (
          <ScanError error={order.error} onRetry={handleRetry} />
        )}
      </div>
    </main>
  );
}
