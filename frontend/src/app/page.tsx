'use client';

import { useState, useEffect, useCallback, useRef, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { createOrder, getOrderStatus, cancelOrder, OrderStatus } from '@/lib/api';
import { isLoggedIn, clearToken } from '@/lib/auth';
import Link from 'next/link';
import VectiScanLogo from '@/components/VectiScanLogo';
import ScanProgress from '@/components/ScanProgress';
import ReportDownload from '@/components/ReportDownload';
import ScanError from '@/components/ScanError';
import PackageSelector, { ScanPackage } from '@/components/PackageSelector';
import ScanTerminal from '@/components/terminal/ScanTerminal';
import { useTerminalFeed } from '@/components/terminal/useTerminalFeed';
import { useWebSocket, WsMessage, AiStrategy, AiConfig } from '@/hooks/useWebSocket';
import ScanIntelligence, { HostNode, ToolOutputEntry } from '@/components/ScanIntelligence';

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
  const [ready, setReady] = useState(false);
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

  // Intelligence panel state
  const [aiStrategy, setAiStrategy] = useState<AiStrategy | null>(null);
  const [aiConfigs, setAiConfigs] = useState<Record<string, AiConfig>>({});
  const [toolOutputs, setToolOutputs] = useState<ToolOutputEntry[]>([]);
  const [intelligenceHosts, setIntelligenceHosts] = useState<HostNode[]>([]);

  const { lines, processStatus, initTerminal, reset: resetTerminal } = useTerminalFeed();

  // Build HostNode list from discovered hosts + AI strategy
  const updateIntelligenceHosts = useCallback((
    discoveredHosts: Array<{ ip: string; fqdns: string[]; status?: string }>,
    strategy: AiStrategy | null,
    currentHost: string | null,
  ) => {
    const skipIps = new Set(
      (strategy?.hosts || []).filter(h => h.action === 'skip').map(h => h.ip)
    );
    // discoveredHosts may be an array or a host_inventory object with .hosts
    const hostList = Array.isArray(discoveredHosts) ? discoveredHosts
      : (discoveredHosts as Record<string, unknown>)?.hosts as typeof discoveredHosts || [];
    const nodes: HostNode[] = hostList.map(h => ({
      ip: h.ip,
      fqdns: h.fqdns,
      status: skipIps.has(h.ip) ? 'skipped' as const
        : h.ip === currentHost ? 'scanning' as const
        : h.status === 'scanned' ? 'scanned' as const
        : 'discovered' as const,
      reasoning: strategy?.hosts.find(s => s.ip === h.ip)?.reasoning,
    }));
    setIntelligenceHosts(nodes);
  }, []);

  // WebSocket message handler
  const handleWsMessage = useCallback((msg: WsMessage) => {
    if (msg.type === 'connected') return;

    // Handle AI events
    if (msg.type === 'ai_strategy' && msg.strategy) {
      setAiStrategy(msg.strategy);
      return;
    }
    if (msg.type === 'ai_config' && msg.ip && msg.config) {
      setAiConfigs(prev => ({ ...prev, [msg.ip!]: msg.config! }));
      return;
    }
    if (msg.type === 'tool_output' && msg.tool && msg.summary) {
      setToolOutputs(prev => [...prev.slice(-50), {
        tool: msg.tool!, host: msg.host || '', summary: msg.summary!, ts: Date.now(),
      }]);
      return;
    }

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
          discoveredHosts: (msg.hosts || []).map((h) => ({ ...h, status: 'pending' })),
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

  // Update intelligence hosts when order changes
  useEffect(() => {
    if (order?.progress.discoveredHosts) {
      updateIntelligenceHosts(
        order.progress.discoveredHosts,
        aiStrategy,
        order.progress.currentHost,
      );
    }
  }, [order?.progress.discoveredHosts, order?.progress.currentHost, aiStrategy, updateIntelligenceHosts]);

  const handleWsConnectionChange = useCallback((connected: boolean) => {
    setWsConnected(connected);
  }, []);

  const { close: closeWs } = useWebSocket(orderId, {
    onMessage: handleWsMessage,
    onConnectionChange: handleWsConnectionChange,
  });

  // Auth check
  useEffect(() => {
    if (!isLoggedIn()) {
      router.replace('/login');
      return;
    }
    setReady(true);
  }, [router]);

  // Resume scan from orderId query param
  useEffect(() => {
    const paramOrderId = searchParams.get('orderId');
    if (paramOrderId && !orderId && ready) {
      setOrderId(paramOrderId);
      startPolling(paramOrderId);
    }
  }, [searchParams, ready]); // eslint-disable-line react-hooks/exhaustive-deps

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

  useEffect(() => {
    if (order && orderId && !showReport && order.status !== 'verification_pending' && order.status !== 'verified') {
      initTerminal(order.domain, order.package);
    }
  }, [order?.domain, order?.package]); // eslint-disable-line react-hooks/exhaustive-deps

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
    } catch { /* keep polling */ }
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

    let trimmed = domain.trim().toLowerCase()
      .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');

    if (!DOMAIN_REGEX.test(trimmed)) {
      setError('Ungültige Domain. Beispiel: beispiel.de');
      return;
    }

    setSubmitting(true);
    try {
      const res = await createOrder(trimmed, selectedPackage);
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
    setDomain('');
    setSelectedPackage('professional');
    setOrderId(null);
    setOrder(null);
    setError(null);
    setCancelling(false);
    setAiStrategy(null);
    setAiConfigs({});
    setToolOutputs([]);
    setIntelligenceHosts([]);
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

  const handleLogout = () => {
    clearToken();
    router.replace('/login');
  };

  const isScanning = orderId && order && order.status !== 'report_complete' && order.status !== 'failed' && order.status !== 'cancelled';

  if (!ready) return null;

  return (
    <main className="min-h-screen flex flex-col items-center justify-center px-4 py-12">
      <div className={`w-full space-y-6 ${isScanning ? 'max-w-7xl' : 'max-w-4xl'}`}>
        {/* Header */}
        {!showReport && (
          <div className="text-center space-y-2">
            <VectiScanLogo className="mb-4" />
            <p className="text-gray-400">Automatisierte Security-Scan-Plattform</p>
            <div className="flex items-center justify-center gap-2 mt-2">
              <Link href="/dashboard" className="bg-[#1e293b] hover:bg-[#253347] text-gray-300 hover:text-white text-sm font-medium px-4 py-2 rounded-lg border border-gray-700 transition-colors">Dashboard</Link>
              <button onClick={handleLogout} className="bg-[#1e293b] hover:bg-[#253347] text-gray-400 hover:text-white text-sm font-medium px-4 py-2 rounded-lg border border-gray-700 transition-colors">Abmelden</button>
            </div>
          </div>
        )}

        {/* Form */}
        {!orderId && !showReport && (
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex flex-col gap-3 max-w-2xl mx-auto">
              <div className="flex gap-3">
                <input type="text" value={domain} onChange={(e) => setDomain(e.target.value)}
                  placeholder="beispiel.de" disabled={submitting}
                  className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono disabled:opacity-50" />
                <button type="submit" disabled={submitting || !domain.trim()}
                  className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-lg transition-colors">
                  {submitting ? 'Startet...' : 'Scan starten'}
                </button>
              </div>
            </div>
            <PackageSelector selected={selectedPackage} onSelect={setSelectedPackage} />
          </form>
        )}

        {error && !orderId && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
        )}

        {/* Scanning: Split-screen command center */}
        {order && order.status !== 'report_complete' && order.status !== 'cancelled' && (
          <>
            <ScanProgress scan={order} onCancel={isScanning ? handleCancel : undefined} cancelling={cancelling} />

            <div className="flex gap-4 items-stretch">
              {/* Left: Terminal */}
              <div className="flex-1 min-w-0 lg:max-w-[48%]">
                <div className="rounded-lg border border-[#1E3A5F]/50 overflow-hidden h-full">
                  <button onClick={() => setTerminalOpen(!terminalOpen)}
                    className="w-full flex items-center justify-between px-4 py-2.5 bg-[#0C1222] hover:bg-[#0F172A] transition-colors">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${isScanning ? 'bg-[#38BDF8] animate-pulse' : order.status === 'failed' ? 'bg-red-500' : 'bg-[#4B7399]'}`} />
                      <span className="text-xs font-mono text-[#4B7399]">Terminal Log</span>
                      <span className="text-xs text-[#1E3A5F] font-mono">{lines.length} lines</span>
                    </div>
                    <span className="text-[#4B7399] text-xs">{terminalOpen ? '\u25B2 Einklappen' : '\u25BC Aufklappen'}</span>
                  </button>
                  {terminalOpen && (
                    <ScanTerminal lines={lines} currentTool={order.progress.currentTool || null}
                      currentHost={order.progress.currentHost || null} isScanning={!!isScanning}
                      isComplete={order.status === 'report_complete'} isError={order.status === 'failed'} compact />
                  )}
                </div>
              </div>

              {/* Right: Intelligence Panel (hidden on mobile) */}
              <div className="hidden lg:block lg:w-[52%] shrink-0">
                <ScanIntelligence
                  domain={order.domain}
                  hosts={intelligenceHosts}
                  currentHost={order.progress.currentHost}
                  currentTool={order.progress.currentTool}
                  currentPhase={order.progress.phase}
                  aiStrategy={aiStrategy}
                  aiConfigs={aiConfigs}
                  toolOutputs={toolOutputs}
                />
              </div>
            </div>
          </>
        )}

        {/* Report download */}
        {showReport && order?.status === 'report_complete' && (
          <div className="animate-fadeIn">
            <ReportDownload orderId={order.id} domain={order.domain} onNewScan={handleRetry} />
          </div>
        )}

        {/* Error/cancelled */}
        {(order?.status === 'failed' || order?.status === 'cancelled') && (
          <ScanError error={order.error} onRetry={handleRetry} />
        )}
      </div>
    </main>
  );
}
