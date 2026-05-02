'use client';

import { useState, useEffect, useCallback, use } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  listOrders, listSubscriptions, getReportDownloadUrl, requestRescan,
  deleteOrderPermanent, getDashboardSummary,
  OrderListItem, Subscription, DashboardSummary,
} from '@/lib/api';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import SeverityCounts from '@/components/SeverityCounts';
import { groupOrders, findGroupByKey, OrderGroup } from '@/lib/grouping';
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
  pending_review:      { bg: 'bg-amber-500/15', text: 'text-amber-400' },
  approved:            { bg: 'bg-emerald-500/15', text: 'text-emerald-400' },
  rejected:            { bg: 'bg-red-500/15',  text: 'text-red-400' },
  report_generating:   { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  report_complete:     { bg: 'bg-slate-700',   text: 'text-slate-300' },
  delivered:           { bg: 'bg-slate-700',   text: 'text-slate-300' },
  failed:              { bg: 'bg-red-500/15',  text: 'text-red-400' },
  cancelled:           { bg: 'bg-red-500/15',  text: 'text-red-400' },
  verified:            { bg: 'bg-blue-500/20', text: 'text-blue-400' },
};

const RISK_BADGE: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border border-red-500/20' },
  HIGH:     { bg: 'bg-red-500/10',    text: 'text-red-400/70', border: 'border border-red-500/15' },
  MEDIUM:   { bg: 'bg-slate-700/50',  text: 'text-slate-400',  border: 'border border-slate-600' },
  LOW:      { bg: 'bg-slate-800',     text: 'text-slate-500',  border: 'border border-slate-700' },
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#EF4444', HIGH: '#F59E0B', MEDIUM: '#3B82F6', LOW: '#22C55E',
};

const RISK_LABELS: Record<string, string> = {
  CRITICAL: 'Kritisch', HIGH: 'Hoch', MEDIUM: 'Mittel', LOW: 'Niedrig',
};

const ACTIVE_STATUSES = new Set([
  'verification_pending', 'verified', 'created', 'queued', 'scanning',
  'passive_intel', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_phase3',
  'scan_complete', 'pending_review', 'approved', 'report_generating',
]);

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

interface PageProps { params: Promise<{ groupKey: string }> }

export default function GroupDetailPage({ params }: PageProps) {
  const router = useRouter();
  const { groupKey: rawGroupKey } = use(params);
  // Next.js url-encodes the [groupKey] segment; the colon in "sub:..."/"dom:..."
  // survives encoding but we still decodeURIComponent so domains work either way.
  const groupKey = decodeURIComponent(rawGroupKey);

  const [ready, setReady] = useState(false);
  const [admin, setAdmin] = useState(false);
  const [orders, setOrders] = useState<OrderListItem[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rescanBusy, setRescanBusy] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    setAdmin(isAdmin());
    setReady(true);
  }, [router]);

  // Parse the route key to drive the per-group dashboard-summary filter
  const summaryFilter = (() => {
    if (groupKey.startsWith('sub:')) return { subscriptionId: groupKey.slice(4) };
    if (groupKey.startsWith('dom:')) return { domain: groupKey.slice(4) };
    if (groupKey.startsWith('ord:')) return { orderId: groupKey.slice(4) };
    return undefined;
  })();

  const fetchData = useCallback(async () => {
    try {
      const [ordersRes, subsRes, summaryRes] = await Promise.all([
        listOrders(),
        listSubscriptions(),
        getDashboardSummary(summaryFilter),
      ]);
      if (ordersRes.success && ordersRes.data) setOrders(ordersRes.data.orders);
      if (subsRes.success && subsRes.data) setSubscriptions(subsRes.data.subscriptions);
      if (summaryRes.success && summaryRes.data) setSummary(summaryRes.data);
      setError(null);
    } catch {
      setError('API nicht erreichbar');
    } finally {
      setLoading(false);
    }
    // summaryFilter is derived from groupKey which only changes on route change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupKey]);

  useEffect(() => {
    if (!ready) return;
    fetchData();
    const interval = setInterval(fetchData, 30_000);
    return () => clearInterval(interval);
  }, [ready, fetchData]);

  if (!ready || loading) return <main className="flex-1 px-4 py-6 md:px-8"><div className="max-w-6xl mx-auto text-gray-500">Lade…</div></main>;

  const groups = groupOrders(orders, subscriptions);
  const group = findGroupByKey(groups, groupKey);

  if (!group) {
    return (
      <main className="flex-1 px-4 py-6 md:px-8">
        <div className="max-w-6xl mx-auto space-y-4">
          <Link href="/dashboard" className="text-xs text-slate-500 hover:text-slate-300">← Zurück zum Dashboard</Link>
          <div className="rounded-xl p-8 text-center" style={{ backgroundColor: '#1E293B' }}>
            <p className="text-slate-300">Paket nicht gefunden.</p>
            <p className="text-xs text-slate-500 mt-2">groupKey: <span className="font-mono">{groupKey}</span></p>
          </div>
        </div>
      </main>
    );
  }

  const sub = group.subscription;
  const agg = group.aggregates;
  const totalSeverity = agg.severityCounts.CRITICAL + agg.severityCounts.HIGH + agg.severityCounts.MEDIUM + agg.severityCounts.LOW;
  const overallRisk = agg.latestRisk || 'LOW';
  const riskColor = RISK_COLORS[overallRisk] || RISK_COLORS.LOW;
  const sortedOrders = [...group.orders].sort((a, b) => {
    const aTs = new Date(a.createdAt).getTime();
    const bTs = new Date(b.createdAt).getTime();
    return bTs - aTs;
  });

  const handleRescan = async (targetId: string, label: string) => {
    if (!sub) return;
    const isAdminTrigger = admin;
    const confirmMsg = isAdminTrigger
      ? `Admin-Re-Scan für ${label} starten? Das Kontingent wird dabei NICHT belastet.`
      : `Re-Scan für ${label} starten? (${sub.maxRescans - sub.rescansUsed} Re-Scans verbleibend)`;
    if (!confirm(confirmMsg)) return;
    setRescanBusy(targetId);
    try {
      const res = await requestRescan(sub.id, targetId);
      if (res.success) {
        await fetchData();
      } else {
        setError(res.error || 'Re-Scan fehlgeschlagen');
      }
    } finally {
      setRescanBusy(null);
    }
  };

  const handleRescanAll = async () => {
    if (!sub) return;
    const approvedCount = (sub.targets ?? []).filter(t => t.status === 'approved').length;
    if (approvedCount === 0) {
      setError('Keine freigegebenen Targets im Abo.');
      return;
    }
    const confirmMsg = admin
      ? `Admin-Re-Scan für alle ${approvedCount} Targets starten? Das Kontingent wird NICHT belastet.`
      : `Re-Scan für alle ${approvedCount} Targets starten? (${sub.maxRescans - sub.rescansUsed} Re-Scans verbleibend — wird als EIN Re-Scan gezählt.)`;
    if (!confirm(confirmMsg)) return;
    setRescanBusy('__all__');
    try {
      const res = await requestRescan(sub.id);
      if (res.success) {
        await fetchData();
      } else {
        setError(res.error || 'Re-Scan fehlgeschlagen');
      }
    } finally {
      setRescanBusy(null);
    }
  };

  const handleDelete = async (order: OrderListItem) => {
    if (!confirm(`Order für ${order.domain} endgültig löschen?`)) return;
    const res = await deleteOrderPermanent(order.id);
    if (res.success) {
      setOrders(prev => prev.filter(o => o.id !== order.id));
    } else {
      setError(res.error || 'Fehler beim Löschen');
    }
  };

  return (
    <main className="flex-1 px-4 py-6 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Breadcrumb */}
        <Link href="/dashboard" className="text-xs text-slate-500 hover:text-slate-300">← Zurück zum Dashboard</Link>

        {/* Header */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
              group.kind === 'subscription'
                ? 'bg-teal-500/15 text-teal-400'
                : 'bg-slate-700 text-slate-400'
            }`}>
              {group.kind === 'subscription' ? 'Abo' : 'Einzelscans'}
            </span>
            <h1 className="text-lg font-semibold text-white">{group.title}</h1>
            <span className="text-sm text-slate-500">{group.subtitle}</span>
          </div>
          <Link href="/scan" className="text-xs px-3 py-1.5 rounded-lg bg-teal-500/10 text-teal-400 hover:bg-teal-500/20 transition-colors">
            + Neuer Scan
          </Link>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-4 py-3 text-sm">{error}</div>
        )}

        {/* Mini-Cockpit */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="rounded-xl p-5 flex items-center gap-4" style={{ backgroundColor: '#1E293B' }}>
            <div className="w-16 h-16 rounded-full flex items-center justify-center text-xl font-bold border-4"
              style={{ borderColor: riskColor, color: riskColor }}>
              {overallRisk === 'CRITICAL' ? '!' : overallRisk === 'HIGH' ? '!!' : overallRisk === 'MEDIUM' ? '~' : '✓'}
            </div>
            <div className="min-w-0">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Aktuelles Risiko</p>
              <p className="text-base font-semibold" style={{ color: riskColor }}>{RISK_LABELS[overallRisk] || overallRisk}</p>
              <p className="text-xs text-slate-500">aus {agg.totalScans} Scan{agg.totalScans !== 1 ? 's' : ''}</p>
            </div>
          </div>
          <div className="rounded-xl p-5" style={{ backgroundColor: '#1E293B' }}>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Befunde (aggregiert)</p>
            {totalSeverity > 0 ? (
              <SeverityCounts counts={agg.severityCounts} />
            ) : (
              <p className="text-sm text-slate-500">Keine Befunde</p>
            )}
          </div>
          <div className="rounded-xl p-5 space-y-1" style={{ backgroundColor: '#1E293B' }}>
            <p className="text-[10px] uppercase tracking-wider text-slate-500">Status</p>
            <p className="text-sm text-white">{agg.activeScans} aktiv · {agg.doneScans} fertig · {agg.failedScans} fehlgeschlagen</p>
            {agg.lastScanAt && <p className="text-xs text-slate-500">Letzter Scan: {formatDate(agg.lastScanAt)}</p>}
          </div>
        </div>

        {/* Subscription details */}
        {sub && (
          <SubscriptionPanel
            sub={sub}
            admin={admin}
            rescanBusy={rescanBusy}
            onRescan={handleRescan}
            onRescanAll={handleRescanAll}
          />
        )}

        {/* Top findings (per group) */}
        {summary && summary.topFindings.length > 0 && (
          <div className="rounded-2xl p-5 space-y-3" style={{ backgroundColor: '#1E293B' }}>
            <h3 className="text-xs font-medium uppercase tracking-wider" style={{ color: '#64748B' }}>
              Dringendster Handlungsbedarf
            </h3>
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
        {summary && summary.topFindings.length === 0 && summary.totalScans > 0 && (
          <div className="rounded-2xl p-6 text-center" style={{ backgroundColor: '#1E293B' }}>
            <p className="text-sm" style={{ color: '#22C55E' }}>Keine kritischen Befunde — gut gemacht!</p>
          </div>
        )}

        {/* Scan list */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-white">Scans dieses Pakets</h2>
          {sortedOrders.length === 0 ? (
            <div className="rounded-xl p-6 text-center text-sm text-slate-500" style={{ backgroundColor: '#1E293B' }}>
              Noch keine Scans. {sub && 'Sobald die Domains verifiziert sind, läuft der erste Scan automatisch.'}
            </div>
          ) : (
            sortedOrders.map(order => (
              <ScanRow key={order.id} order={order} admin={admin} onDelete={handleDelete} />
            ))
          )}
        </div>
      </div>
    </main>
  );
}

// ────────────────────────────────────────────────────────────
// Subscription panel
// ────────────────────────────────────────────────────────────
function SubscriptionPanel({
  sub, admin, rescanBusy, onRescan, onRescanAll,
}: {
  sub: Subscription;
  admin: boolean;
  rescanBusy: string | null;
  onRescan: (targetId: string, label: string) => void;
  onRescanAll: () => void;
}) {
  const intervalLabel = ({ weekly: 'Wöchentlich', monthly: 'Monatlich', quarterly: 'Quartalsweise' } as Record<string, string>)[sub.scanInterval] || sub.scanInterval;
  const rescansLeft = sub.maxRescans - sub.rescansUsed;
  const targets = sub.targets ?? [];
  const approvedCount = targets.filter(t => t.status === 'approved').length;
  const canRescanAll = approvedCount > 0 && (admin || rescansLeft > 0);
  return (
    <div className="rounded-xl p-5 space-y-4" style={{ backgroundColor: '#1E293B' }}>
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2 text-xs">
          <span className="text-teal-400 bg-teal-500/15 px-2 py-0.5 rounded uppercase font-bold tracking-wider">{sub.package}</span>
          <span className="text-slate-500">{intervalLabel}</span>
          <span className="text-slate-700">·</span>
          <span className="text-slate-500" title="Verbleibende Re-Scans aus dem Abo-Kontingent. Admin-Re-Scans werden NICHT angerechnet.">
            {rescansLeft}/{sub.maxRescans} Re-Scans
          </span>
          {admin && <span className="text-slate-700">·</span>}
          {admin && <span className="text-amber-400/80">Admin-Re-Scan ohne Kontingent</span>}
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {canRescanAll && (
            <button
              onClick={onRescanAll}
              disabled={rescanBusy === '__all__'}
              className="text-xs text-teal-300 hover:text-teal-200 disabled:opacity-50 font-semibold px-3 py-1.5 bg-teal-400/15 hover:bg-teal-400/25 rounded transition-colors"
              title={admin ? 'Alle Targets in einem Lauf scannen (kein Kontingent)' : `Alle ${approvedCount} Targets in einem Lauf scannen (zaehlt als 1 Re-Scan)`}
            >
              {rescanBusy === '__all__' ? 'Startet…' : (admin ? `Admin-Re-Scan (alle ${approvedCount})` : `Re-Scan (alle ${approvedCount})`)}
            </button>
          )}
          {sub.expiresAt && (
            <span className="text-xs text-slate-500">Läuft bis {new Date(sub.expiresAt).toLocaleDateString('de-DE')}</span>
          )}
        </div>
      </div>

      <div className="space-y-1.5">
        {targets.map(t => {
          const statusMap: Record<string, { dot: string; label: string }> = {
            approved: { dot: 'bg-green-500', label: 'Aktiv' },
            pending_precheck: { dot: 'bg-slate-400', label: 'Pre-Check läuft' },
            precheck_running: { dot: 'bg-slate-400', label: 'Pre-Check läuft' },
            precheck_complete: { dot: 'bg-amber-500', label: 'Wartet auf Freigabe' },
            pending_review: { dot: 'bg-amber-500', label: 'Wartet auf Freigabe' },
            rejected: { dot: 'bg-red-500', label: 'Abgelehnt' },
            removed: { dot: 'bg-gray-600', label: 'Entfernt' },
          };
          const s = statusMap[t.status] || { dot: 'bg-gray-500', label: t.status };
          const label = t.canonical || t.raw_input;
          const canRescan = t.status === 'approved' && (admin || rescansLeft > 0);
          return (
            <div key={t.id} className="flex items-center justify-between py-1 border-b border-gray-700/50 last:border-0">
              <div className="flex items-center gap-2 min-w-0">
                <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                <span className="text-sm text-white font-mono truncate">{label}</span>
                <span className="text-[10px] text-gray-500">{s.label}</span>
              </div>
              {canRescan && (
                <button
                  onClick={() => onRescan(t.id, label)}
                  disabled={rescanBusy === t.id}
                  className="text-[10px] text-teal-400 hover:text-teal-300 disabled:opacity-50 font-medium px-2 py-1 bg-teal-400/10 rounded transition-colors"
                >
                  {rescanBusy === t.id ? 'Startet…' : (admin ? 'Admin-Re-Scan' : 'Re-Scan')}
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────
// Single scan row
// ────────────────────────────────────────────────────────────
function ScanRow({ order, admin, onDelete }: {
  order: OrderListItem; admin: boolean; onDelete: (o: OrderListItem) => void;
}) {
  const router = useRouter();
  const statusLabel = PHASE_LABELS[order.status] || order.status;
  const statusStyle = PHASE_COLORS[order.status] || { bg: 'bg-slate-700', text: 'text-slate-400' };
  const active = ACTIVE_STATUSES.has(order.status);
  const needsVerify = order.status === 'verification_pending' || order.status === 'verified';
  const isRunning = active && !needsVerify;
  const isDone = order.status === 'report_complete' || order.status === 'delivered';
  const hasDetails = !['created', 'queued', 'verification_pending', 'verified'].includes(order.status);
  const duration = formatDuration(order.startedAt, order.finishedAt);
  const riskBadge = order.overallRisk ? RISK_BADGE[order.overallRisk.toUpperCase()] : null;
  // Karten-Click-Ziel:
  // - verification_pending / verified → /verify/<id> (eigene UX-Rolle)
  // - alles andere mit Detail-Page → /scan/<id> (Modern-View, default seit Mai 2026)
  // - created/queued (noch keine Daten) → nicht klickbar
  const rowHref = needsVerify ? `/verify/${order.id}` : (hasDetails ? `/scan/${order.id}` : undefined);

  return (
    <div
      className={`bg-[#1e293b] hover:bg-[#253347] rounded-lg border border-gray-800 p-4 transition-colors ${rowHref ? 'cursor-pointer' : ''}`}
      onClick={rowHref ? () => router.push(rowHref) : undefined}
    >
      <div className="flex items-center justify-between gap-2 mb-2 flex-wrap">
        <div className="flex items-center gap-3 min-w-0">
          <span className="font-mono text-blue-400 text-sm truncate">{order.domain}</span>
          {order.isRescan && <span className="text-[10px] text-amber-400/70 bg-amber-400/10 px-1.5 py-0.5 rounded">Re-Scan</span>}
          {isDone && order.severityCounts && <SeverityCounts counts={order.severityCounts} />}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {riskBadge && isDone && (
            <span className={`${riskBadge.bg} ${riskBadge.text} ${riskBadge.border} text-xs font-bold px-2 py-0.5 rounded uppercase`}>
              {order.overallRisk}
            </span>
          )}
          <span className={`${statusStyle.bg} ${statusStyle.text} text-xs font-medium px-2.5 py-1 rounded inline-flex items-center gap-1.5`}>
            {active && <span className="w-1.5 h-1.5 bg-current rounded-full animate-pulse" />}
            {statusLabel}
          </span>
        </div>
      </div>

      {isRunning && order.hostsTotal > 0 && (
        <div className="mb-2">
          <div className="flex justify-between text-xs text-gray-500 mb-1">
            <span className="font-mono truncate">
              {order.currentTool && <>{order.currentTool}{order.currentHost ? ` ${'→'} ${order.currentHost}` : ''}</>}
            </span>
            <span className="shrink-0 ml-2">{order.hostsCompleted}/{order.hostsTotal} Hosts</span>
          </div>
          <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 rounded-full transition-all duration-1000"
                 style={{ width: `${Math.round((order.hostsCompleted / order.hostsTotal) * 100)}%` }} />
          </div>
        </div>
      )}

      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap text-xs text-slate-600">
          <span className="font-mono uppercase tracking-wider text-slate-500">{order.package}</span>
          {order.hostsTotal > 0 && <><span className="text-slate-700">·</span><span>{order.hostsTotal} Hosts</span></>}
          {duration && <><span className="text-slate-700">·</span><span>{duration}</span></>}
          <span className="text-slate-700">·</span>
          <span>{order.startedAt ? formatDate(order.startedAt) : formatDate(order.createdAt)}</span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {/* "Details"-Button entfernt — die ganze Card ist jetzt klickbar
              und fuehrt direkt zur Modern-View (/scan/<id>). */}
          {needsVerify && (
            <button onClick={e => { e.stopPropagation(); router.push(`/verify/${order.id}`); }}
              className="text-xs text-slate-400 hover:text-blue-400 font-medium px-3 py-1.5 bg-slate-800/50 hover:bg-slate-700/50 rounded-lg transition-colors">
              Verifizieren
            </button>
          )}
          {isDone && order.hasReport && (
            <a href={getReportDownloadUrl(order.id)} onClick={e => e.stopPropagation()}
              className="text-xs text-slate-400 hover:text-blue-400 font-medium px-3 py-1.5 bg-slate-800/50 hover:bg-slate-700/50 rounded-lg transition-colors inline-block">
              PDF
            </a>
          )}
          {admin && (
            <button onClick={e => { e.stopPropagation(); onDelete(order); }}
              className="text-xs text-slate-400 hover:text-red-400 font-medium px-3 py-1.5 bg-slate-800/50 hover:bg-slate-700/50 rounded-lg transition-colors">
              Löschen
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
