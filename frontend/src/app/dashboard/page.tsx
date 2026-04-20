'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { listOrders, getReportDownloadUrl, deleteOrderPermanent, listSubscriptions, requestRescan, getDashboardSummary, OrderListItem, Subscription, DashboardSummary } from '@/lib/api';
import { isLoggedIn, isAdmin, getUser, clearToken } from '@/lib/auth';
import SeverityCounts from '@/components/SeverityCounts';

import { STATUS_LABELS, formatDuration as fmtDur } from '@/lib/utils';

const PHASE_LABELS = STATUS_LABELS;

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
  return fmtDur(min);
}

export default function Dashboard() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [userEmail, setUserEmail] = useState<string | null>(null);

  const [orders, setOrders] = useState<OrderListItem[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const PAGE_SIZE = 20;

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
      const [ordersRes, subsRes, summaryRes] = await Promise.all([listOrders(), listSubscriptions(), getDashboardSummary()]);
      if (ordersRes.success && ordersRes.data) {
        setOrders(ordersRes.data.orders);
        setLastUpdate(new Date());
        setError(null);
      } else {
        setError(ordersRes.error || 'Fehler beim Laden');
      }
      if (subsRes.success && subsRes.data) {
        setSubscriptions(subsRes.data.subscriptions);
      }
      if (summaryRes.success && summaryRes.data) {
        setSummary(summaryRes.data);
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

  const filtered = filterOrders(orders, filter)
    .filter(o => !searchQuery || o.domain.toLowerCase().includes(searchQuery.toLowerCase()));
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
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

        {/* Subscriptions */}
        {subscriptions.length > 0 && (
          <div className="space-y-3">
            {subscriptions.filter(s => s.status === 'active').map((sub) => {
              const pkgLabel = PACKAGE_STYLES[sub.package]?.label || sub.package.toUpperCase();
              const intervalLabel = { weekly: 'Wöchentlich', monthly: 'Monatlich', quarterly: 'Quartalsweise' }[sub.scanInterval] || sub.scanInterval;
              const verifiedDomains = sub.domains.filter(d => d.status === 'verified');
              const pendingDomains = sub.domains.filter(d => d.status === 'pending_approval');
              const rescansLeft = sub.maxRescans - sub.rescansUsed;

              return (
                <div key={sub.id} className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold tracking-wider text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded">{pkgLabel}</span>
                      <span className="text-xs text-green-400 bg-green-400/10 px-2 py-0.5 rounded">Aktiv</span>
                      <span className="text-xs text-gray-500">{intervalLabel}</span>
                    </div>
                    <div className="text-xs text-gray-500">
                      {sub.expiresAt && <>Läuft bis {new Date(sub.expiresAt).toLocaleDateString('de-DE')}</>}
                    </div>
                  </div>

                  {/* Domains */}
                  <div className="space-y-1.5">
                    {sub.domains.map((d) => {
                      const statusMap: Record<string, { dot: string; label: string }> = {
                        verified: { dot: 'bg-green-500', label: 'Aktiv' },
                        pending_approval: { dot: 'bg-amber-500', label: 'Wartet auf Freigabe' },
                        rejected: { dot: 'bg-red-500', label: 'Abgelehnt' },
                      };
                      const s = statusMap[d.status] || { dot: 'bg-gray-500', label: d.status };
                      return (
                        <div key={d.id} className="flex items-center justify-between py-1 border-b border-gray-700/50 last:border-0">
                          <div className="flex items-center gap-2">
                            <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                            <span className="text-sm text-white font-mono">{d.domain}</span>
                            <span className="text-[10px] text-gray-500">{s.label}</span>
                          </div>
                          {d.status === 'verified' && rescansLeft > 0 && (
                            <button
                              onClick={async () => {
                                if (!confirm(`Re-Scan fur ${d.domain} starten? (${rescansLeft} Re-Scans verbleibend)`)) return;
                                const res = await requestRescan(sub.id, d.domain);
                                if (res.success) {
                                  fetchOrders();
                                } else {
                                  setError(res.error || 'Re-Scan fehlgeschlagen');
                                }
                              }}
                              className="text-[10px] text-blue-400 hover:text-blue-300 font-medium px-2 py-1 bg-blue-400/10 rounded transition-colors"
                            >
                              Re-Scan
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {/* Meta */}
                  <div className="flex items-center gap-4 text-xs text-gray-500">
                    <span>{verifiedDomains.length} aktive Domain{verifiedDomains.length !== 1 ? 's' : ''}</span>
                    {pendingDomains.length > 0 && <span className="text-amber-400">{pendingDomains.length} ausstehend</span>}
                    <span>{rescansLeft}/{sub.maxRescans} Re-Scans</span>
                    {sub.lastScanAt && <span>Letzter Scan: {formatDate(sub.lastScanAt)}</span>}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Upsell banner if no subscriptions */}
        {!loading && subscriptions.length === 0 && orders.length > 0 && (
          <Link href="/subscribe"
            className="block bg-[#1e293b] border border-blue-800/30 rounded-lg p-3 text-sm text-blue-400 hover:text-blue-300 hover:bg-[#253347] transition-colors">
            Automatisieren Sie Ihre Scans mit einem Abo &rarr;
          </Link>
        )}

        {/* Security Cockpit — Risk Gauge + Top Findings */}
        {summary && summary.totalScans > 0 && (
          <div className="space-y-4">
            {/* Risk Gauge */}
            <div className="rounded-2xl p-6 flex flex-col sm:flex-row items-center gap-6" style={{ backgroundColor: '#1E293B' }}>
              <div className="flex items-center gap-4">
                <div className="w-20 h-20 rounded-full flex items-center justify-center text-2xl font-bold border-4"
                  style={{
                    borderColor: { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#3B82F6', LOW: '#22C55E' }[summary.overallRisk] || '#22C55E',
                    color: { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#3B82F6', LOW: '#22C55E' }[summary.overallRisk] || '#22C55E',
                  }}>
                  {summary.overallRisk === 'CRITICAL' ? '!' : summary.overallRisk === 'HIGH' ? '!!' : summary.overallRisk === 'MEDIUM' ? '~' : '✓'}
                </div>
                <div>
                  <p className="text-lg font-semibold" style={{ color: '#F8FAFC' }}>
                    Gesamtrisiko: <span style={{ color: { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#3B82F6', LOW: '#22C55E' }[summary.overallRisk] || '#22C55E' }}>
                      {{ CRITICAL: 'Kritisch', HIGH: 'Hoch', MEDIUM: 'Mittel', LOW: 'Niedrig' }[summary.overallRisk] || summary.overallRisk}
                    </span>
                  </p>
                  <p className="text-xs" style={{ color: '#94A3B8' }}>
                    {summary.domains} Domain{summary.domains !== 1 ? 's' : ''} · {summary.totalFindings} offene Befunde
                    {summary.criticalCount > 0 && <span style={{ color: '#EF4444' }}> · {summary.criticalCount} kritisch</span>}
                    {summary.highCount > 0 && <span style={{ color: '#F59E0B' }}> · {summary.highCount} hoch</span>}
                  </p>
                </div>
              </div>
            </div>

            {/* Top Findings */}
            {summary.topFindings.length > 0 && (
              <div className="rounded-2xl p-5 space-y-3" style={{ backgroundColor: '#1E293B' }}>
                <h3 className="text-xs font-medium uppercase tracking-wider" style={{ color: '#64748B' }}>Dringendster Handlungsbedarf</h3>
                {summary.topFindings.map((f, i) => (
                  <Link key={i} href={`/scan/${f.orderId}`}
                    className="flex items-center justify-between p-3 rounded-xl transition-colors hover:bg-[#253347]">
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="text-xs font-bold px-2 py-0.5 rounded"
                        style={{
                          backgroundColor: { CRITICAL: '#EF444420', HIGH: '#F59E0B20', MEDIUM: '#3B82F620' }[f.severity] || '#3B82F620',
                          color: { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#3B82F6' }[f.severity] || '#3B82F6',
                        }}>
                        {f.cvss.toFixed(1)}
                      </span>
                      <div className="min-w-0">
                        <p className="text-sm truncate" style={{ color: '#F8FAFC' }}>{f.title}</p>
                        <p className="text-[11px]" style={{ color: '#64748B' }}>{f.domain}</p>
                      </div>
                    </div>
                    <span className="text-xs flex-shrink-0" style={{ color: '#2DD4BF' }}>Details →</span>
                  </Link>
                ))}
              </div>
            )}

            {summary.topFindings.length === 0 && (
              <div className="rounded-2xl p-6 text-center" style={{ backgroundColor: '#1E293B' }}>
                <p className="text-sm" style={{ color: '#22C55E' }}>Keine kritischen Befunde — gut gemacht!</p>
              </div>
            )}
          </div>
        )}

        {/* KPI Summary Cards */}
        {!loading && orders.length > 0 && (() => {
          const done = orders.filter(o => ['report_complete', 'delivered'].includes(o.status));
          const activeScans = orders.filter(o => ['scanning', 'queued', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_phase3', 'report_generating'].includes(o.status));
          const domains = new Set(orders.map(o => o.domain));
          const highestRisk = done.reduce((max, o) => {
            const r = o.overallRisk?.toUpperCase();
            if (r === 'CRITICAL') return 'CRITICAL';
            if (r === 'HIGH' && max !== 'CRITICAL') return 'HIGH';
            if (r === 'MEDIUM' && !['CRITICAL', 'HIGH'].includes(max)) return 'MEDIUM';
            return max;
          }, 'LOW');
          const riskColor = { CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#3B82F6', LOW: '#22C55E' }[highestRisk] || '#22C55E';
          return (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="rounded-xl p-4" style={{ backgroundColor: '#1E293B' }}>
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: '#64748B' }}>Domains</p>
                <p className="text-2xl font-bold" style={{ color: '#F8FAFC' }}>{domains.size}</p>
              </div>
              <div className="rounded-xl p-4" style={{ backgroundColor: '#1E293B' }}>
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: '#64748B' }}>Scans gesamt</p>
                <p className="text-2xl font-bold" style={{ color: '#F8FAFC' }}>{orders.length}</p>
              </div>
              <div className="rounded-xl p-4" style={{ backgroundColor: '#1E293B' }}>
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: '#64748B' }}>Aktive Scans</p>
                <p className="text-2xl font-bold" style={{ color: '#2DD4BF' }}>{activeScans.length}</p>
              </div>
              <div className="rounded-xl p-4" style={{ backgroundColor: '#1E293B' }}>
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: '#64748B' }}>Gesamtrisiko</p>
                <p className="text-2xl font-bold" style={{ color: riskColor }}>{highestRisk}</p>
              </div>
            </div>
          );
        })()}

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

        {/* Search */}
        <input
          type="text"
          value={searchQuery}
          onChange={e => { setSearchQuery(e.target.value); setPage(1); }}
          placeholder="Domain suchen..."
          className="w-full sm:max-w-xs bg-[#1e293b] border border-gray-800 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-[#2DD4BF] focus:ring-1 focus:ring-[#2DD4BF]"
        />

        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
        )}
        {loading && <div className="text-center py-12 text-gray-500">Lade Aufträge...</div>}
        {!loading && orders.length === 0 && (
          <div className="text-center py-16 space-y-4">
            <div className="w-16 h-16 rounded-full mx-auto mb-4 flex items-center justify-center" style={{ backgroundColor: '#2DD4BF12', border: '2px solid #2DD4BF30' }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#2DD4BF" strokeWidth="1.5" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <h2 className="text-lg font-semibold" style={{ color: '#F8FAFC' }}>Willkommen bei VectiScan</h2>
            <p className="text-sm max-w-sm mx-auto" style={{ color: '#94A3B8' }}>
              In wenigen Minuten wissen Sie, wie sicher Ihre IT-Infrastruktur ist. Starten Sie Ihren ersten Scan oder erstellen Sie ein Abo für regelmäßige Überwachung.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
              <Link href="/welcome" className="px-6 py-3 rounded-lg text-sm font-semibold transition-all cta-glow"
                style={{ backgroundColor: '#2DD4BF', color: '#0F172A' }}>Ersten Scan starten</Link>
              <Link href="/subscribe" className="px-6 py-3 rounded-lg text-sm font-medium transition-colors"
                style={{ color: '#F8FAFC', border: '1px solid rgba(45,212,191,0.25)' }}>Abo erstellen</Link>
            </div>
          </div>
        )}

        {/* Orders list */}
        {!loading && filtered.length > 0 && (
          <div className="space-y-4">
            {paginated.map((order) => {
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
                        {admin && order.email !== userEmail && <span className="text-xs text-slate-600 truncate hidden sm:inline">{order.email}</span>}
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

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-center gap-2 pt-4">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                  className="text-xs px-3 py-1.5 rounded-md disabled:opacity-30 transition-colors"
                  style={{ color: '#94A3B8', border: '1px solid rgba(45,212,191,0.15)' }}>Zurück</button>
                <span className="text-xs" style={{ color: '#64748B' }}>Seite {page} von {totalPages}</span>
                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                  className="text-xs px-3 py-1.5 rounded-md disabled:opacity-30 transition-colors"
                  style={{ color: '#94A3B8', border: '1px solid rgba(45,212,191,0.15)' }}>Weiter</button>
              </div>
            )}
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
