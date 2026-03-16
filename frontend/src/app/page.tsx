'use client';

import { useState, useEffect, useCallback, useRef, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { createOrder, getOrderStatus, cancelOrder, getOrderEvents, OrderStatus } from '@/lib/api';
import { isLoggedIn } from '@/lib/auth';
import ScanProgress from '@/components/ScanProgress';
import ReportDownload from '@/components/ReportDownload';
import ScanError from '@/components/ScanError';
import PackageSelector, { ScanPackage } from '@/components/PackageSelector';
import ScanTerminal from '@/components/terminal/ScanTerminal';
import { useTerminalFeed } from '@/components/terminal/useTerminalFeed';
import { useWebSocket, WsMessage, AiStrategy, AiConfig } from '@/hooks/useWebSocket';
import { HostNode, ToolOutputEntry } from '@/components/intelligence/constants';
import RadarTopology from '@/components/intelligence/RadarTopology';
import MetricsGrid from '@/components/intelligence/MetricsGrid';
import HostDiscoveryMatrix from '@/components/intelligence/HostDiscoveryMatrix';
import AiDecisionFeed from '@/components/intelligence/AiDecisionFeed';

// Hex divider between sections
function HexDivider() {
  const [hex, setHex] = useState(['0000', '0000']);
  useEffect(() => {
    const h = () => Math.random().toString(16).slice(2, 6).toUpperCase();
    const iv = setInterval(() => setHex([h(), h()]), 1500);
    return () => clearInterval(iv);
  }, []);
  return (
    <div className="flex items-center gap-1 px-3 py-0.5 shrink-0 select-none">
      <span className="text-[7px] font-mono text-slate-700">0x{hex[0]}</span>
      <span className="flex-1 h-px" style={{ background: 'linear-gradient(to right, rgba(30,58,95,0.4), rgba(30,58,95,0.15), rgba(30,58,95,0.4))' }} />
      <span className="text-[7px] font-mono text-slate-700">0x{hex[1]}</span>
    </div>
  );
}

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
  const [wsConnected, setWsConnected] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Intelligence state
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

  useEffect(() => {
    if (order?.progress.discoveredHosts) {
      updateIntelligenceHosts(order.progress.discoveredHosts, aiStrategy, order.progress.currentHost);
    }
  }, [order?.progress.discoveredHosts, order?.progress.currentHost, aiStrategy, updateIntelligenceHosts]);

  const handleWsConnectionChange = useCallback((connected: boolean) => {
    setWsConnected(connected);
  }, []);

  const { close: closeWs } = useWebSocket(orderId, {
    onMessage: handleWsMessage,
    onConnectionChange: handleWsConnectionChange,
  });

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    setReady(true);
  }, [router]);

  // Load persisted events when resuming a scan (late-join)
  const loadEvents = useCallback(async (id: string) => {
    try {
      const res = await getOrderEvents(id);
      if (res.success && res.data) {
        if (res.data.aiStrategy) setAiStrategy(res.data.aiStrategy as AiStrategy);
        if (res.data.aiConfigs) setAiConfigs(res.data.aiConfigs as Record<string, AiConfig>);
        if (res.data.toolOutputs?.length) {
          setToolOutputs(res.data.toolOutputs.map(t => ({
            ...t, ts: new Date(t.ts).getTime(),
          })));
        }
      }
    } catch { /* non-critical */ }
  }, []);

  useEffect(() => {
    const paramOrderId = searchParams.get('orderId');
    if (paramOrderId && !orderId && ready) {
      setOrderId(paramOrderId);
      startPolling(paramOrderId);
      loadEvents(paramOrderId);
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
    if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null; }
  }, []);

  const pollStatus = useCallback(async (id: string) => {
    try {
      const res = await getOrderStatus(id);
      if (res.success && res.data) { setOrder(res.data); processStatus(res.data); }
    } catch { /* keep polling */ }
  }, [processStatus]);

  const startPolling = useCallback((id: string) => {
    stopPolling();
    pollStatus(id);
    intervalRef.current = setInterval(() => pollStatus(id), wsConnected ? 15000 : 3000);
  }, [pollStatus, stopPolling, wsConnected]);

  useEffect(() => { return () => stopPolling(); }, [stopPolling]);

  useEffect(() => {
    if (!order) return;
    if (order.status === 'report_complete') {
      stopPolling(); closeWs();
      setTimeout(() => setShowReport(true), 500);
    } else if (order.status === 'failed' || order.status === 'cancelled') {
      stopPolling(); closeWs();
    }
  }, [order?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null); setOrder(null); setOrderId(null);
    let trimmed = domain.trim().toLowerCase()
      .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
    if (!DOMAIN_REGEX.test(trimmed)) { setError('Ungültige Domain. Beispiel: beispiel.de'); return; }
    setSubmitting(true);
    try {
      const res = await createOrder(trimmed, selectedPackage);
      if (res.success && res.data) { router.push(`/verify/${res.data.id}`); }
      else { setError(res.error || 'Unbekannter Fehler'); }
    } catch { setError('API nicht erreichbar. Läuft der Backend-Server?'); }
    finally { setSubmitting(false); }
  };

  const handleRetry = () => {
    stopPolling(); closeWs(); resetTerminal();
    setShowReport(false); setDomain(''); setSelectedPackage('professional');
    setOrderId(null); setOrder(null); setError(null); setCancelling(false);
    setAiStrategy(null); setAiConfigs({}); setToolOutputs([]); setIntelligenceHosts([]);
  };

  const handleCancel = async () => {
    if (!orderId) return;
    setCancelling(true);
    try { await cancelOrder(orderId); stopPolling(); handleRetry(); }
    catch { setCancelling(false); }
  };

  const isScanning = orderId && order && order.status !== 'report_complete' && order.status !== 'failed' && order.status !== 'cancelled';

  if (!ready) return null;

  // ─── Scan Form (not scanning) ──────────────────────────
  if (!orderId && !showReport) {
    return (
      <main className="flex-1 flex flex-col items-center justify-center px-4">
        <div className="w-full max-w-2xl space-y-6">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex gap-3">
              <input type="text" value={domain} onChange={(e) => setDomain(e.target.value)}
                placeholder="beispiel.de" disabled={submitting}
                className="flex-1 bg-[#1e293b] border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono disabled:opacity-50" />
              <button type="submit" disabled={submitting || !domain.trim()}
                className="bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:cursor-not-allowed text-white font-medium px-6 py-3 rounded-lg transition-colors">
                {submitting ? 'Startet...' : 'Scan starten'}
              </button>
            </div>
            <PackageSelector selected={selectedPackage} onSelect={setSelectedPackage} />
          </form>
          {error && (
            <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
          )}
        </div>
      </main>
    );
  }

  // ─── Report Download ───────────────────────────────────
  if (showReport && order?.status === 'report_complete') {
    return (
      <main className="flex-1 flex flex-col items-center justify-center px-4">
        <div className="w-full max-w-4xl animate-fadeIn">
          <ReportDownload orderId={order.id} domain={order.domain} onNewScan={handleRetry} />
        </div>
      </main>
    );
  }

  // ─── Error / Cancelled ─────────────────────────────────
  if (order?.status === 'failed' || order?.status === 'cancelled') {
    return (
      <main className="flex-1 flex flex-col items-center justify-center px-4">
        <div className="w-full max-w-4xl">
          <ScanError error={order.error} onRetry={handleRetry} />
        </div>
      </main>
    );
  }

  // ─── LIVEVIEW — CSS Grid Operations Center ─────────────
  if (order && isScanning) {
    const panelBorder = 'rgba(30,58,95,0.3)';
    const panelBg = 'rgba(12,18,34,0.6)';

    return (
      <main className="grid gap-2 px-3 py-2 overflow-hidden"
        style={{
          height: 'calc(100vh - 40px)',
          gridTemplateAreas: '"progress progress progress" "terminal ailog sidebar" "terminal ailog hosts"',
          gridTemplateRows: 'auto 1fr auto',
          gridTemplateColumns: '1fr 1fr 260px',
        }}>

        {/* ─── Row 1: ScanProgress ──────────────────── */}
        <div style={{ gridArea: 'progress' }}>
          <ScanProgress scan={order} onCancel={handleCancel} cancelling={cancelling} />
        </div>

        {/* ─── Row 2 Left: Terminal Log ─────────────── */}
        <div className="rounded-lg border overflow-hidden flex flex-col"
          style={{ gridArea: 'terminal', borderColor: panelBorder, background: panelBg }}>
          <div className="flex items-center px-3 shrink-0 border-b"
            style={{ height: 28, borderColor: panelBorder, background: '#0C1222' }}>
            <span className={`w-1.5 h-1.5 rounded-full mr-2 ${isScanning ? 'bg-blue-500 animate-pulse' : 'bg-slate-600'}`} />
            <span className="text-[10px] font-mono uppercase tracking-wider text-blue-500">Terminal Log</span>
            <span className="ml-auto text-[9px] font-mono text-slate-700">{lines.length} lines</span>
          </div>
          <div className="flex-1 min-h-0">
            <ScanTerminal lines={lines} currentTool={order.progress.currentTool || null}
              currentHost={order.progress.currentHost || null} isScanning={!!isScanning}
              isComplete={order.status === 'report_complete'} isError={order.status === 'failed'} compact />
          </div>
        </div>

        {/* ─── Right: Radar + Metrics ───────────────── */}
        <div className="hidden lg:flex rounded-lg border overflow-hidden flex-col"
          style={{ gridArea: 'sidebar', borderColor: panelBorder, background: panelBg }}>
          <div className="flex items-center px-3 shrink-0 border-b"
            style={{ height: 28, borderColor: panelBorder, background: '#0C1222' }}>
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mr-2" />
            <span className="text-[10px] font-mono uppercase tracking-wider text-blue-500">Tactical Map</span>
          </div>
          <div className="shrink-0 flex items-center justify-center py-1">
            <RadarTopology
              domain={order.domain}
              hosts={intelligenceHosts}
              currentHost={order.progress.currentHost}
              toolOutputs={toolOutputs}
            />
          </div>
          <HexDivider />
          <div className="flex-1 min-h-0 flex flex-col justify-center">
            <MetricsGrid
              currentPhase={order.progress.phase}
              currentTool={order.progress.currentTool}
              hosts={intelligenceHosts}
              toolOutputs={toolOutputs}
            />
          </div>
        </div>

        {/* ─── Row 2 Right: AI Decision Log ─────────── */}
        <div className="rounded-lg border overflow-hidden flex flex-col"
          style={{ gridArea: 'ailog', borderColor: panelBorder, background: panelBg }}>
          <div className="flex items-center px-3 shrink-0 border-b"
            style={{ height: 28, borderColor: panelBorder, background: '#0C1222' }}>
            <span className={`w-1.5 h-1.5 rounded-full mr-2 ${aiStrategy ? 'bg-blue-500 animate-pulse' : 'bg-slate-600'}`} />
            <span className="text-[10px] font-mono uppercase tracking-wider text-blue-500">AI Decision Log</span>
            <span className="ml-auto text-[9px] font-mono text-slate-700">
              {toolOutputs.length > 0 ? `${toolOutputs.length}` : ''}
            </span>
          </div>
          <div className="flex-1 min-h-0">
            <AiDecisionFeed
              aiStrategy={aiStrategy}
              aiConfigs={aiConfigs}
              hosts={intelligenceHosts}
              toolOutputs={toolOutputs}
            />
          </div>
        </div>

        {/* ─── Right Bottom: Discovered Hosts ─────────── */}
        <div className="hidden lg:flex rounded-lg border overflow-hidden flex-col"
          style={{ gridArea: 'hosts', borderColor: panelBorder, background: panelBg }}>
          <div className="flex items-center px-3 shrink-0 border-b"
            style={{ height: 28, borderColor: panelBorder, background: '#0C1222' }}>
            <span className={`w-1.5 h-1.5 rounded-full mr-2 ${intelligenceHosts.length > 0 ? 'bg-blue-500' : 'bg-slate-600'}`} />
            <span className="text-[10px] font-mono uppercase tracking-wider text-blue-500">Discovered Hosts</span>
            <span className="ml-auto text-[9px] font-mono text-slate-700">{intelligenceHosts.length} hosts</span>
          </div>
          <div className="flex-1 min-h-0">
            <HostDiscoveryMatrix
              hosts={intelligenceHosts}
              currentHost={order.progress.currentHost}
              aiStrategy={aiStrategy}
            />
          </div>
        </div>
      </main>
    );
  }

  return null;
}
