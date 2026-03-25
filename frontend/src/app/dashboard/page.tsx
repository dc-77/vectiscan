'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { listOrders, getReportDownloadUrl, deleteOrderPermanent, OrderListItem } from '@/lib/api';
import { isLoggedIn, isAdmin, getUser, clearToken } from '@/lib/auth';
import SeverityCounts from '@/components/SeverityCounts';

const PHASE_LABELS: Record<string, string> = {
  verification_pending: 'Verifizierung',
  created: 'Erstellt',
  queued: 'In Warteschlange',
  scanning: 'Startet...',
  passive_intel: 'Passive Intel',
  dns_recon: 'DNS-Recon',
  scan_phase1: 'Phase 1',
  scan_phase2: 'Phase 2',
  scan_phase3: 'Phase 3',
  scan_complete: 'Scan fertig',
  report_generating: 'Report...',
  report_complete: 'Fertig',
  failed: 'Fehlgeschlagen',
  cancelled: 'Abgebrochen',
  verified: 'Verifiziert',
};

const PHASE_COLORS: Record<string, { bg: string; text: string }> = {
  verification_pending: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  created:             { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  queued:              { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scanning:            { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  passive_intel:       { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  dns_recon:           { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scan_phase1:         { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scan_phase2:         { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scan_phase3:         { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  scan_complete:       { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  report_generating:   { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  report_complete:     { bg: 'bg-slate-700',   text: 'text-slate-300' },
  failed:              { bg: 'bg-red-500/15',  text: 'text-red-400' },
  cancelled:           { bg: 'bg-red-500/15',  text: 'text-red-400' },
  verified:            { bg: 'bg-blue-500/20', text: 'text-blue-400' },
};

const PACKAGE_STYLES: Record<string, { label: string }> = {
  // v2 package names
  webcheck:     { label: 'WEBCHECK' },
  perimeter:    { label: 'PERIMETER' },
  compliance:   { label: 'COMPLIANCE' },
  supplychain:  { label: 'SUPPLY' },
  insurance:    { label: 'INSURANCE' },
  tlscompliance: { label: 'TLS-AUDIT' },
  // Legacy aliases
  basic:        { label: 'WEBCHECK' },
  professional: { label: 'PERIMETER' },
  nis2:         { label: 'COMPLIANCE' },
};

const RISK_BADGE: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border border-red-500/20' },
  HIGH:     { bg: 'bg-red-500/10',    text: 'text-red-400/70', border: 'border border-red-500/15' },
  MEDIUM:   { bg: 'bg-slate-700/50',  text: 'text-slate-400',  border: 'border border-slate-600' },
  LOW:      { bg: 'bg-slate-800',     text: 'text-slate-500',  border: 'border border-slate-700' },
};

type StatusFilter = 'all' | 'active' | 'done' | 'failed';
// Detail tabs moved to /scan/[orderId] page

const ACTIVE_STATUSES = ['verification_pending', 'verified', 'created', 'queued', 'scanning', 'passive_intel', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_phase3', 'scan_complete', 'report_generating'];
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

function formatDuration(startedAt: string | null, finishedAt: string | null): string | null {
  if (!startedAt || !finishedAt) return null;
  const ms = new Date(finishedAt).getTime() - new Date(startedAt).getTime();
  const min = Math.round(ms / 60000);
  if (min < 1) return '< 1 Min';
  return `${min} Min`;
}

export default function Dashboard() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [userEmail, setUserEmail] = useState<string | null>(null);

  const [orders, setOrders] = useState<OrderListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<StatusFilter>('all');
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  // Detail panel removed — dedicated /scan/[orderId] page handles details

  useEffect(() => {
    if (!isLoggedIn()) {
      router.replace('/login');
      return;
    }
    setAdmin(isAdmin());
    setUserEmail(getUser()?.email || null);
    setReady(true);
  }, [router]);

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
    if (!ready) return;
    fetchOrders();
    const interval = setInterval(fetchOrders, 30000);
    return () => clearInterval(interval);
  }, [ready, fetchOrders]);

  const handleLogout = () => {
    clearToken();
    router.replace('/login');
  };

  const handleDelete = async (order: OrderListItem) => {
    if (!confirm(`Order für ${order.domain} endgültig löschen? Dies kann nicht rückgängig gemacht werden.`)) return;
    try {
      const res = await deleteOrderPermanent(order.id);
      if (res.success) {
        setOrders((prev) => prev.filter((o) => o.id !== order.id));
      } else {
        setError(res.error || 'Fehler beim Löschen');
      }
    } catch {
      setError('Fehler beim Löschen');
    }
  };

  const filtered = filterOrders(orders, filter);
  const counts = {
    all: orders.length,
    active: orders.filter(o => isActive(o.status)).length,
    done: orders.filter(o => DONE_STATUSES.includes(o.status)).length,
    failed: orders.filter(o => FAILED_STATUSES.includes(o.status)).length,
  };

  if (!ready) return null;

  return (
    <main className="flex-1 px-4 py-6 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Title */}
        <h1 className="text-lg font-semibold text-white">Dashboard</h1>

        {/* Filter pills */}
        <div className="flex items-center gap-2 flex-wrap">
          {([
            ['all', 'Alle', counts.all],
            ['active', 'Aktiv', counts.active],
            ['done', 'Fertig', counts.done],
            ['failed', 'Fehlgeschlagen', counts.failed],
          ] as [StatusFilter, string, number][]).map(([key, label, count]) => (
            <button key={key} onClick={() => setFilter(key)}
              className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${
                filter === key ? 'bg-blue-500/15 text-blue-400 ring-1 ring-blue-500/30' : 'text-slate-500 hover:text-slate-300'
              }`}
            >{label} ({count})</button>
          ))}
          {lastUpdate && (
            <span className="ml-auto text-xs text-gray-600 font-mono">Aktualisiert: {lastUpdate.toLocaleTimeString('de-DE')}</span>
          )}
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
        )}
        {loading && <div className="text-center py-12 text-gray-500">Lade Aufträge...</div>}
        {!loading && orders.length === 0 && (
          <div className="text-center py-16 space-y-4">
            <p className="text-gray-500 text-lg">Noch keine Aufträge</p>
            <Link href="/" className="inline-block bg-blue-600 hover:bg-blue-500 text-white font-medium px-6 py-3 rounded-lg transition-colors">Ersten Scan starten</Link>
          </div>
        )}

        {/* Orders list */}
        {!loading && filtered.length > 0 && (
          <div className="space-y-4">
            {filtered.map((order) => {
              const pkg = PACKAGE_STYLES[order.package] || PACKAGE_STYLES.professional;
              const statusLabel = PHASE_LABELS[order.status] || order.status;
              const statusStyle = PHASE_COLORS[order.status] || { bg: 'bg-slate-700', text: 'text-slate-400' };
              const active = isActive(order.status);
              const needsVerify = order.status === 'verification_pending' || order.status === 'verified';
              const isRunning = active && !needsVerify;
              const isDone = order.status === 'report_complete';
              const hasDetails = !['created', 'queued', 'verification_pending', 'verified'].includes(order.status);
              // Detail expansion removed — uses /scan/[orderId]
              const duration = formatDuration(order.startedAt, order.finishedAt);
              const riskBadge = order.overallRisk ? RISK_BADGE[order.overallRisk.toUpperCase()] : null;

              const rowHref = needsVerify ? `/verify/${order.id}` : isRunning ? `/?orderId=${order.id}` : undefined;

              return (
                <div key={order.id} className="space-y-0">
                  <div
                    className={`bg-[#1e293b] hover:bg-[#253347] rounded-lg border border-gray-800 p-5 transition-colors ${rowHref ? 'cursor-pointer' : ''}`}
                    onClick={rowHref ? () => router.push(rowHref) : undefined}
                  >
                    {/* Row 1: Domain + Severity Counts + Risk + Status */}
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <span className="font-mono text-blue-400 text-sm truncate">{order.domain}</span>
                        {admin && <span className="text-xs text-slate-600 truncate hidden sm:inline">{order.email}</span>}
                        {isDone && order.severityCounts && (
                          <SeverityCounts counts={order.severityCounts} />
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {riskBadge && isDone && (
                          <span className={`${riskBadge.bg} ${riskBadge.text} ${riskBadge.border} text-xs font-bold px-2 py-0.5 rounded uppercase`}>
                            {order.overallRisk}
                          </span>
                        )}
                        {isDone && order.businessImpactScore != null && order.businessImpactScore > 0 && (
                          <span className="text-[10px] font-mono text-slate-500" title="Business Impact Score">
                            BIS {order.businessImpactScore.toFixed(1)}
                          </span>
                        )}
                        <span className={`${statusStyle.bg} ${statusStyle.text} text-xs font-medium px-2.5 py-1 rounded inline-flex items-center gap-1.5`}>
                          {active && <span className="w-1.5 h-1.5 bg-current rounded-full animate-pulse" />}
                          {statusLabel}
                        </span>
                      </div>
                    </div>

                    {/* Progress bar for running scans */}
                    {isRunning && order.hostsTotal > 0 && (
                      <div className="mb-2">
                        <div className="flex justify-between text-xs text-gray-500 mb-1">
                          <span className="font-mono truncate">
                            {order.currentTool && <>{order.currentTool}{order.currentHost ? ` \u2192 ${order.currentHost}` : ''}</>}
                          </span>
                          <span className="shrink-0 ml-2">{order.hostsCompleted}/{order.hostsTotal} Hosts</span>
                        </div>
                        <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                          <div className="h-full bg-blue-500 rounded-full transition-all duration-1000"
                               style={{ width: `${Math.round((order.hostsCompleted / order.hostsTotal) * 100)}%` }} />
                        </div>
                      </div>
                    )}

                    {/* Row 2: Package + Meta + Actions */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5 flex-wrap text-xs text-slate-600">
                        <span className="font-mono uppercase tracking-wider text-slate-500">{pkg.label}</span>
                        {order.hostsTotal > 0 && (
                          <><span className="text-slate-700">&middot;</span><span>{order.hostsTotal} Hosts</span></>
                        )}
                        {duration && (
                          <><span className="text-slate-700">&middot;</span><span>{duration}</span></>
                        )}
                        <span className="text-slate-700">&middot;</span>
                        <span>{order.startedAt ? formatDate(order.startedAt) : formatDate(order.createdAt)}</span>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {hasDetails && (
                          <Link href={`/scan/${order.id}`} onClick={(e) => e.stopPropagation()}
                            className="text-xs font-medium px-3 py-1.5 rounded-lg transition-colors text-slate-400 hover:text-blue-400 bg-slate-800/50 hover:bg-slate-700/50">
                            Details
                          </Link>
                        )}
                        {needsVerify && (
                          <button onClick={(e) => { e.stopPropagation(); router.push(`/verify/${order.id}`); }}
                            className="text-xs text-slate-400 hover:text-blue-400 font-medium px-3 py-1.5 bg-slate-800/50 hover:bg-slate-700/50 rounded-lg transition-colors">
                            Verifizieren
                          </button>
                        )}
                        {isRunning && (
                          <button onClick={(e) => { e.stopPropagation(); router.push(`/?orderId=${order.id}`); }}
                            className="text-xs text-blue-400 hover:text-blue-300 font-medium px-3 py-1.5 bg-slate-800/50 hover:bg-slate-700/50 rounded-lg transition-colors">
                            Live View
                          </button>
                        )}
                        {isDone && order.hasReport && (
                          <a href={getReportDownloadUrl(order.id)} onClick={(e) => e.stopPropagation()}
                            className="text-xs text-slate-400 hover:text-blue-400 font-medium px-3 py-1.5 bg-slate-800/50 hover:bg-slate-700/50 rounded-lg transition-colors inline-block">
                            PDF
                          </a>
                        )}
                        {admin && (
                          <button onClick={(e) => { e.stopPropagation(); handleDelete(order); }}
                            className="text-xs text-slate-400 hover:text-red-400 font-medium px-3 py-1.5 bg-slate-800/50 hover:bg-slate-700/50 rounded-lg transition-colors">
                            Löschen
                          </button>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Detail panel removed — use /scan/[orderId] page */}
                </div>
              );
            })}
          </div>
        )}

        {!loading && orders.length > 0 && filtered.length === 0 && (
          <div className="text-center py-12 text-gray-500">Keine Aufträge mit diesem Filter.</div>
        )}
      </div>
    </main>
  );
}

// RawResultsPanel moved to /scan/[orderId] detail page
