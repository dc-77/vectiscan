'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { listOrders, deleteOrderPermanent, listSubscriptions, OrderListItem, Subscription } from '@/lib/api';
import { isLoggedIn, isAdmin, clearToken } from '@/lib/auth';
import SeverityCounts from '@/components/SeverityCounts';
import { groupOrders, OrderGroup } from '@/lib/grouping';

import { STATUS_LABELS } from '@/lib/utils';

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

type StatusFilter = 'all' | 'subscription' | 'domain' | 'active' | 'done' | 'failed';

function groupMatchesFilter(group: OrderGroup, filter: StatusFilter): boolean {
  if (filter === 'all') return true;
  if (filter === 'subscription') return group.kind === 'subscription';
  if (filter === 'domain') return group.kind === 'domain';
  if (group.orders.length === 0) return false;
  if (filter === 'active') return group.aggregates.activeScans > 0;
  if (filter === 'done') return group.aggregates.doneScans > 0;
  if (filter === 'failed') return group.aggregates.failedScans > 0;
  return true;
}

function groupMatchesSearch(group: OrderGroup, search: string): boolean {
  if (!search) return true;
  const q = search.toLowerCase();
  if (group.title.toLowerCase().includes(q)) return true;
  return group.domains.some(d => d.toLowerCase().includes(q));
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('de-DE', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

export default function Dashboard() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [admin, setAdmin] = useState(false);

  const [orders, setOrders] = useState<OrderListItem[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
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
    setReady(true);
  }, [router]);

  const fetchOrders = useCallback(async () => {
    try {
      const [ordersRes, subsRes] = await Promise.all([listOrders(), listSubscriptions()]);
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

  const groups = groupOrders(orders, subscriptions);
  const filteredGroups = groups
    .filter(g => groupMatchesFilter(g, filter))
    .filter(g => groupMatchesSearch(g, searchQuery));
  const totalPages = Math.max(1, Math.ceil(filteredGroups.length / PAGE_SIZE));
  const paginatedGroups = filteredGroups.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const counts = {
    all: groups.length,
    subscription: groups.filter(g => g.kind === 'subscription').length,
    domain: groups.filter(g => g.kind === 'domain').length,
    active: groups.filter(g => g.aggregates.activeScans > 0).length,
    done: groups.filter(g => g.aggregates.doneScans > 0).length,
    failed: groups.filter(g => g.aggregates.failedScans > 0).length,
  };

  if (!ready) return null;

  return (
    <main className="flex-1 px-4 py-6 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Title */}
        <h1 className="text-lg font-semibold text-white">Dashboard</h1>

        {/* Upsell banner if no subscriptions */}
        {!loading && subscriptions.length === 0 && orders.length > 0 && (
          <Link href="/subscribe"
            className="block bg-[#1e293b] border border-blue-800/30 rounded-lg p-3 text-sm text-blue-400 hover:text-blue-300 hover:bg-[#253347] transition-colors">
            Automatisieren Sie Ihre Scans mit einem Abo &rarr;
          </Link>
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
            ['subscription', 'Abo', counts.subscription],
            ['domain', 'Einzelscan', counts.domain],
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
            <span className="ml-auto text-xs text-gray-600">Zuletzt aktualisiert: {lastUpdate.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })} Uhr</span>
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

        {/* Group cards */}
        {!loading && filteredGroups.length > 0 && (
          <div className="space-y-4">
            {paginatedGroups.map((group) => (
              <GroupCard key={group.key} group={group} admin={admin} />
            ))}

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

        {!loading && groups.length > 0 && filteredGroups.length === 0 && (
          <div className="text-center py-12 text-gray-500">Keine Pakete mit diesem Filter.</div>
        )}

        {/* Admin: Delete legacy individual orders inline */}
        {admin && groups.some(g => g.kind === 'domain') && (
          <details className="text-xs text-slate-500">
            <summary className="cursor-pointer hover:text-slate-300">Admin: Einzelne Scans verwalten</summary>
            <div className="mt-2 space-y-1 max-h-64 overflow-auto pr-2">
              {orders.filter(o => !o.subscriptionId).map(o => (
                <div key={o.id} className="flex items-center justify-between gap-2 py-1 border-b border-gray-800">
                  <span className="font-mono text-slate-400 truncate">{o.domain} &middot; {o.id.slice(0, 8)}</span>
                  <button onClick={() => handleDelete(o)} className="text-red-400 hover:text-red-300">Löschen</button>
                </div>
              ))}
            </div>
          </details>
        )}
      </div>
    </main>
  );
}

// ────────────────────────────────────────────────────────────
// Group card — replaces both subscription cards and flat scan rows
// ────────────────────────────────────────────────────────────
function GroupCard({ group, admin }: { group: OrderGroup; admin: boolean }) {
  const router = useRouter();
  const sub = group.subscription;
  const agg = group.aggregates;
  const intervalLabel = sub
    ? ({ weekly: 'Wöchentlich', monthly: 'Monatlich', quarterly: 'Quartalsweise' } as Record<string, string>)[sub.scanInterval] || sub.scanInterval
    : null;
  const pkgLabel = sub
    ? PACKAGE_STYLES[sub.package]?.label || sub.package.toUpperCase()
    : null;
  const riskBadge = agg.latestRisk ? RISK_BADGE[agg.latestRisk] : null;
  const statusLabel = agg.latestStatus ? (PHASE_LABELS[agg.latestStatus] || agg.latestStatus) : null;
  const statusStyle = agg.latestStatus ? (PHASE_COLORS[agg.latestStatus] || { bg: 'bg-slate-700', text: 'text-slate-400' }) : null;
  const isActiveGroup = agg.activeScans > 0;
  const totalSeverity = agg.severityCounts.CRITICAL + agg.severityCounts.HIGH + agg.severityCounts.MEDIUM + agg.severityCounts.LOW;
  const groupHref = `/scans/${group.key}`;

  return (
    <div
      className="bg-[#1e293b] hover:bg-[#253347] rounded-lg border border-gray-800 p-5 transition-colors cursor-pointer"
      onClick={() => router.push(groupHref)}
    >
      {/* Header row */}
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-3 min-w-0 flex-wrap">
          <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
            group.kind === 'subscription'
              ? 'bg-teal-500/15 text-teal-400'
              : group.kind === 'order'
              ? 'bg-indigo-500/15 text-indigo-300'
              : 'bg-slate-700 text-slate-400'
          }`}>
            {group.kind === 'subscription' ? 'Abo' : group.kind === 'order' ? 'Multi-Target' : 'Einzelscans'}
          </span>
          <span className="font-semibold text-white text-sm truncate">{group.title}</span>
          <span className="text-xs text-slate-500 truncate">{group.subtitle}</span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {riskBadge && (
            <span className={`${riskBadge.bg} ${riskBadge.text} ${riskBadge.border} text-xs font-bold px-2 py-0.5 rounded uppercase`}>
              {agg.latestRisk}
            </span>
          )}
          {statusLabel && statusStyle && (
            <span className={`${statusStyle.bg} ${statusStyle.text} text-xs font-medium px-2.5 py-1 rounded inline-flex items-center gap-1.5`}>
              {isActiveGroup && <span className="w-1.5 h-1.5 bg-current rounded-full animate-pulse" />}
              {statusLabel}
            </span>
          )}
        </div>
      </div>

      {/* Aggregated severity */}
      {totalSeverity > 0 && (
        <div className="mb-3">
          <SeverityCounts counts={agg.severityCounts} />
        </div>
      )}

      {/* Meta row */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap text-xs text-slate-600">
          {pkgLabel && (
            <>
              <span className="font-mono uppercase tracking-wider text-slate-500">{pkgLabel}</span>
              <span className="text-slate-700">&middot;</span>
            </>
          )}
          {intervalLabel && (
            <><span>{intervalLabel}</span><span className="text-slate-700">&middot;</span></>
          )}
          <span>{agg.totalScans} Scan{agg.totalScans !== 1 ? 's' : ''}</span>
          {agg.activeScans > 0 && (
            <><span className="text-slate-700">&middot;</span><span className="text-blue-400">{agg.activeScans} aktiv</span></>
          )}
          {agg.failedScans > 0 && (
            <><span className="text-slate-700">&middot;</span><span className="text-red-400">{agg.failedScans} fehlgeschlagen</span></>
          )}
          {sub && (
            <>
              <span className="text-slate-700">&middot;</span>
              <span title="Verbleibende Re-Scans aus dem Abo-Kontingent">{sub.maxRescans - sub.rescansUsed}/{sub.maxRescans} Re-Scans</span>
            </>
          )}
          {agg.lastScanAt && (
            <><span className="text-slate-700">&middot;</span><span>Zuletzt {formatDate(agg.lastScanAt)}</span></>
          )}
          {!agg.lastScanAt && sub && (
            <span className="text-slate-500">Noch keine Scans</span>
          )}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {admin && group.orders[0]?.email && <span className="text-[10px] text-slate-600 hidden sm:inline">{group.orders[0].email}</span>}
          <Link href={groupHref} onClick={(e) => e.stopPropagation()}
            className="text-xs font-medium px-3 py-1.5 rounded-lg transition-colors text-slate-400 hover:text-blue-400 bg-slate-800/50 hover:bg-slate-700/50">
            Öffnen →
          </Link>
        </div>
      </div>
    </div>
  );
}

