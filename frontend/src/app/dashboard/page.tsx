'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { listOrders, getReportDownloadUrl, verifyPassword, getScanResults, OrderListItem, ScanResult } from '@/lib/api';
import VectiScanLogo from '@/components/VectiScanLogo';

const PHASE_LABELS: Record<string, string> = {
  verification_pending: 'Verifizierung',
  created: 'Erstellt',
  scanning: 'Startet...',
  dns_recon: 'DNS-Recon',
  scan_phase1: 'Phase 1',
  scan_phase2: 'Phase 2',
  scan_complete: 'Scan fertig',
  report_generating: 'Report...',
  report_complete: 'Fertig',
  failed: 'Fehlgeschlagen',
  cancelled: 'Abgebrochen',
  verified: 'Verifiziert',
};

const PHASE_COLORS: Record<string, string> = {
  verification_pending: 'bg-yellow-600',
  created: 'bg-gray-500',
  scanning: 'bg-blue-500',
  dns_recon: 'bg-purple-500',
  scan_phase1: 'bg-blue-500',
  scan_phase2: 'bg-cyan-500',
  scan_complete: 'bg-teal-500',
  report_generating: 'bg-amber-500',
  report_complete: 'bg-green-500',
  failed: 'bg-red-500',
  cancelled: 'bg-orange-500',
  verified: 'bg-teal-500',
};

const PACKAGE_STYLES: Record<string, { label: string; bg: string; text: string }> = {
  basic:        { label: 'Basic',        bg: 'bg-sky-500/20', text: 'text-sky-400' },
  professional: { label: 'Professional', bg: 'bg-blue-500/20', text: 'text-blue-400' },
  nis2:         { label: 'NIS2',         bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
};

type StatusFilter = 'all' | 'active' | 'done' | 'failed';

const ACTIVE_STATUSES = ['verification_pending', 'verified', 'created', 'scanning', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_complete', 'report_generating'];
const DONE_STATUSES = ['report_complete'];
const FAILED_STATUSES = ['failed', 'cancelled'];

function isActive(status: string) { return ACTIVE_STATUSES.includes(status); }

function filterOrders(orders: OrderListItem[], filter: StatusFilter): OrderListItem[] {
  if (filter === 'all') return orders;
  if (filter === 'active') return orders.filter(o => isActive(o.status));
  if (filter === 'done') return orders.filter(o => DONE_STATUSES.includes(o.status));
  if (filter === 'failed') return orders.filter(o => FAILED_STATUSES.includes(o.status));
  return orders;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function Dashboard() {
  const router = useRouter();
  const [authenticated, setAuthenticated] = useState(false);
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authLoading, setAuthLoading] = useState(false);

  const [orders, setOrders] = useState<OrderListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<StatusFilter>('all');
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  // Raw scan results viewer
  const [expandedResults, setExpandedResults] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<Record<string, ScanResult[]>>({});
  const [resultsLoading, setResultsLoading] = useState<string | null>(null);
  const [expandedTool, setExpandedTool] = useState<string | null>(null);

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

  const fetchOrders = useCallback(async () => {
    try {
      const res = await listOrders();
      if (res.success && res.data) {
        setOrders(res.data.orders);
        setLastUpdate(new Date());
        setError(null);
      } else {
        setError(res.error || 'Fehler beim Laden');
      }
    } catch {
      setError('API nicht erreichbar');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    fetchOrders();
    const interval = setInterval(fetchOrders, 30000);
    return () => clearInterval(interval);
  }, [authenticated, fetchOrders]);

  const toggleResults = useCallback(async (orderId: string) => {
    if (expandedResults === orderId) {
      setExpandedResults(null);
      setExpandedTool(null);
      return;
    }
    setExpandedResults(orderId);
    setExpandedTool(null);

    // Only fetch if not already cached
    if (!scanResults[orderId]) {
      setResultsLoading(orderId);
      try {
        const res = await getScanResults(orderId);
        if (res.success && res.data) {
          setScanResults(prev => ({ ...prev, [orderId]: res.data!.results }));
        }
      } catch {
        // silently fail
      } finally {
        setResultsLoading(null);
      }
    }
  }, [expandedResults, scanResults]);

  const filtered = filterOrders(orders, filter);

  const counts = {
    all: orders.length,
    active: orders.filter(o => isActive(o.status)).length,
    done: orders.filter(o => DONE_STATUSES.includes(o.status)).length,
    failed: orders.filter(o => FAILED_STATUSES.includes(o.status)).length,
  };

  if (!authenticated) {
    return (
      <main className="min-h-screen flex flex-col items-center justify-center px-4 py-12">
        <div className="w-full max-w-sm space-y-6">
          <div className="text-center space-y-2">
            <VectiScanLogo className="mb-4" />
            <p className="text-gray-400">Zugang zum Dashboard</p>
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
    <main className="min-h-screen px-4 py-8 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className="hidden sm:block"><VectiScanLogo /></div>
            <h1 className="text-lg sm:text-xl font-semibold text-white truncate">Dashboard</h1>
          </div>
          <Link
            href="/"
            className="bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-3 py-2 rounded-lg transition-colors shrink-0 whitespace-nowrap"
          >
            + Neuer Scan
          </Link>
        </div>

        {/* Filter pills */}
        <div className="flex items-center gap-2 flex-wrap">
          {([
            ['all', 'Alle', counts.all],
            ['active', 'Aktiv', counts.active],
            ['done', 'Fertig', counts.done],
            ['failed', 'Fehlgeschlagen', counts.failed],
          ] as [StatusFilter, string, number][]).map(([key, label, count]) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${
                filter === key
                  ? 'bg-blue-600 text-white'
                  : 'bg-[#1e293b] text-gray-400 hover:text-white hover:bg-[#253347]'
              }`}
            >
              {label} ({count})
            </button>
          ))}
          {lastUpdate && (
            <span className="ml-auto text-xs text-gray-600 font-mono">
              Aktualisiert: {lastUpdate.toLocaleTimeString('de-DE')}
            </span>
          )}
        </div>

        {/* Error */}
        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">
            {error}
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="text-center py-12 text-gray-500">Lade Aufträge...</div>
        )}

        {/* Empty state */}
        {!loading && orders.length === 0 && (
          <div className="text-center py-16 space-y-4">
            <p className="text-gray-500 text-lg">Noch keine Aufträge</p>
            <Link
              href="/"
              className="inline-block bg-blue-600 hover:bg-blue-500 text-white font-medium px-6 py-3 rounded-lg transition-colors"
            >
              Ersten Scan starten
            </Link>
          </div>
        )}

        {/* Orders list */}
        {!loading && filtered.length > 0 && (
          <div className="space-y-3">
            {filtered.map((order) => {
              const pkg = PACKAGE_STYLES[order.package] || PACKAGE_STYLES.professional;
              const statusLabel = PHASE_LABELS[order.status] || order.status;
              const statusColor = PHASE_COLORS[order.status] || 'bg-gray-500';
              const active = isActive(order.status);
              const needsVerify = order.status === 'verification_pending' || order.status === 'verified';
              const isRunning = active && !needsVerify;

              const rowHref = needsVerify
                ? `/verify/${order.id}`
                : isRunning
                  ? `/?orderId=${order.id}`
                  : undefined;

              // Show results button for orders that have completed scanning
              const hasResults = ['scan_complete', 'report_generating', 'report_complete'].includes(order.status);
              const isExpanded = expandedResults === order.id;
              const orderResults = scanResults[order.id] || [];
              const isLoadingResults = resultsLoading === order.id;

              // Group results by phase and host
              const groupedResults: Record<string, ScanResult[]> = {};
              for (const r of orderResults) {
                const key = `Phase ${r.phase}${r.hostIp ? ` — ${r.hostIp}` : ''}`;
                if (!groupedResults[key]) groupedResults[key] = [];
                groupedResults[key].push(r);
              }

              return (
                <div key={order.id} className="space-y-0">
                  <div
                    className={`bg-[#1e293b] hover:bg-[#253347] rounded-lg border border-gray-800 p-4 transition-colors ${rowHref ? 'cursor-pointer' : ''} ${isExpanded ? 'rounded-b-none border-b-0' : ''}`}
                    onClick={rowHref ? () => router.push(rowHref) : undefined}
                  >
                    {/* Row 1: Domain + Status */}
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <span className="font-mono text-cyan-400 text-sm truncate">{order.domain}</span>
                      <span className={`${statusColor} text-white text-xs font-medium px-2.5 py-1 rounded-full inline-flex items-center gap-1.5 shrink-0`}>
                        {active && (
                          <span className="w-1.5 h-1.5 bg-white rounded-full animate-pulse" />
                        )}
                        {statusLabel}
                      </span>
                    </div>

                    {/* Progress bar for running scans */}
                    {isRunning && order.hostsTotal > 0 && (
                      <div className="mb-2">
                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                          <span className="font-mono truncate">
                            {order.currentTool && (
                              <>{order.currentTool}{order.currentHost ? ` → ${order.currentHost}` : ''}</>
                            )}
                          </span>
                          <span className="shrink-0 ml-2">{order.hostsCompleted}/{order.hostsTotal} Hosts</span>
                        </div>
                        <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-blue-500 rounded-full transition-all duration-1000"
                            style={{ width: `${Math.round((order.hostsCompleted / order.hostsTotal) * 100)}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {/* Row 2: Package + Date + Action */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-medium px-2 py-0.5 rounded ${pkg.bg} ${pkg.text}`}>
                          {pkg.label}
                        </span>
                        <span className="text-xs text-gray-600">{formatDate(order.createdAt)}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {hasResults && (
                          <button
                            onClick={(e) => { e.stopPropagation(); toggleResults(order.id); }}
                            className={`text-xs font-medium px-3 py-1.5 rounded-lg transition-colors ${
                              isExpanded
                                ? 'text-purple-300 bg-purple-400/20'
                                : 'text-purple-400 hover:text-purple-300 bg-purple-400/10'
                            }`}
                          >
                            {isExpanded ? 'Ergebnisse ausblenden' : 'Scan-Ergebnisse'}
                          </button>
                        )}
                        {needsVerify && (
                          <button
                            onClick={(e) => { e.stopPropagation(); router.push(`/verify/${order.id}`); }}
                            className="text-xs text-yellow-400 hover:text-yellow-300 font-medium px-3 py-1.5 bg-yellow-400/10 rounded-lg transition-colors"
                          >
                            Verifizieren
                          </button>
                        )}
                        {isRunning && (
                          <button
                            onClick={(e) => { e.stopPropagation(); router.push(`/?orderId=${order.id}`); }}
                            className="text-xs text-blue-400 hover:text-blue-300 font-medium px-3 py-1.5 bg-blue-400/10 rounded-lg transition-colors"
                          >
                            Live View
                          </button>
                        )}
                        {order.status === 'report_complete' && order.hasReport && (
                          <a
                            href={getReportDownloadUrl(order.id)}
                            className="text-xs text-green-400 hover:text-green-300 font-medium px-3 py-1.5 bg-green-400/10 rounded-lg transition-colors inline-block"
                            onClick={(e) => e.stopPropagation()}
                          >
                            PDF Download
                          </a>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Expandable raw results panel */}
                  {isExpanded && (
                    <div className="bg-[#0f172a] border border-gray-800 border-t-0 rounded-b-lg overflow-hidden">
                      {isLoadingResults && (
                        <div className="px-4 py-6 text-center text-gray-500 text-sm">
                          Scan-Ergebnisse laden...
                        </div>
                      )}

                      {!isLoadingResults && orderResults.length === 0 && (
                        <div className="px-4 py-6 text-center text-gray-600 text-sm">
                          Keine Scan-Ergebnisse vorhanden.
                        </div>
                      )}

                      {!isLoadingResults && orderResults.length > 0 && (
                        <div className="divide-y divide-gray-800/50">
                          {Object.entries(groupedResults).map(([group, results]) => (
                            <div key={group}>
                              <div className="px-4 py-2 bg-[#1e293b]/50 text-xs font-medium text-gray-400 uppercase tracking-wider">
                                {group}
                              </div>
                              <div className="divide-y divide-gray-800/30">
                                {results.map((result) => {
                                  const toolId = `${order.id}-${result.id}`;
                                  const isToolExpanded = expandedTool === toolId;
                                  const exitOk = result.exitCode === 0 || result.exitCode === 1;
                                  const durationSec = result.durationMs ? (result.durationMs / 1000).toFixed(1) : '?';

                                  return (
                                    <div key={result.id}>
                                      <button
                                        onClick={() => setExpandedTool(isToolExpanded ? null : toolId)}
                                        className="w-full px-4 py-2.5 flex items-center justify-between gap-3 hover:bg-[#1e293b]/30 transition-colors text-left"
                                      >
                                        <div className="flex items-center gap-2 min-w-0">
                                          <span className={`w-2 h-2 rounded-full shrink-0 ${exitOk ? 'bg-green-500' : 'bg-red-500'}`} />
                                          <span className="text-sm font-mono text-cyan-400 truncate">{result.toolName}</span>
                                        </div>
                                        <div className="flex items-center gap-3 shrink-0 text-xs text-gray-500">
                                          <span>{durationSec}s</span>
                                          <span className={`font-mono ${exitOk ? 'text-green-600' : 'text-red-600'}`}>
                                            exit {result.exitCode}
                                          </span>
                                          <span className="text-gray-700">{isToolExpanded ? '▲' : '▼'}</span>
                                        </div>
                                      </button>

                                      {isToolExpanded && result.rawOutput && (
                                        <div className="px-4 pb-3">
                                          <pre className="bg-[#0c1222] border border-gray-800 rounded-lg p-3 text-xs font-mono text-gray-400 overflow-x-auto max-h-80 overflow-y-auto whitespace-pre-wrap break-all"
                                               style={{ scrollbarWidth: 'thin', scrollbarColor: '#1E3A5F #0C1222' }}
                                          >
                                            {result.rawOutput}
                                          </pre>
                                        </div>
                                      )}

                                      {isToolExpanded && !result.rawOutput && (
                                        <div className="px-4 pb-3 text-xs text-gray-600 italic">
                                          Keine Rohausgabe gespeichert.
                                        </div>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Filtered empty */}
        {!loading && orders.length > 0 && filtered.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            Keine Aufträge mit diesem Filter.
          </div>
        )}
      </div>
    </main>
  );
}
