'use client';

// ── Scans-Liste /scans (VEC-306 Konzept §5.4) ───────────────────
// Konsolidierte Order-/Abos-Übersicht mit Filter-Chips +
// einheitlichem StateView-Empty. Delegiert zur GroupCard-Logik
// aus dem bestehenden Dashboard; nutzt DS-Primitive.

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { listOrders, listSubscriptions, OrderListItem, Subscription } from '@/lib/api';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import { groupOrders, OrderGroup } from '@/lib/grouping';
import SeverityCounts from '@/components/SeverityCounts';
import { StatusChip } from '@/components/ds';
import { StateView } from '@/components/ds';
import { SkeletonList } from '@/components/ds';

type Filter = 'all' | 'active' | 'done' | 'failed';

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function groupMatchesFilter(g: OrderGroup, f: Filter) {
  if (f === 'all') return true;
  if (f === 'active') return g.aggregates.activeScans > 0;
  if (f === 'done') return g.aggregates.doneScans > 0;
  if (f === 'failed') return g.aggregates.failedScans > 0;
  return true;
}

function ScanGroupCard({ group }: { group: OrderGroup }) {
  const router = useRouter();
  const agg = group.aggregates;
  const latestStatus = agg.latestStatus;

  return (
    <div
      className="rounded-lg p-4 border cursor-pointer transition-colors hover:border-[var(--border-subtle)]"
      style={{ backgroundColor: 'var(--surface)', borderColor: 'var(--border-muted)' }}
      onClick={() => router.push(`/scans/${group.key}`)}
      role="link"
      tabIndex={0}
      onKeyDown={e => e.key === 'Enter' && router.push(`/scans/${group.key}`)}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="min-w-0">
          <p className="text-sm font-semibold truncate" style={{ color: 'var(--text)' }}>{group.title}</p>
          {group.subtitle && <p className="text-xs truncate mt-0.5" style={{ color: 'var(--text-dim)' }}>{group.subtitle}</p>}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {latestStatus && <StatusChip status={latestStatus} size="sm" />}
        </div>
      </div>

      {(agg.severityCounts.CRITICAL + agg.severityCounts.HIGH + agg.severityCounts.MEDIUM + agg.severityCounts.LOW) > 0 && (
        <div className="mb-2">
          <SeverityCounts counts={agg.severityCounts} />
        </div>
      )}

      <div className="flex items-center justify-between gap-2 mt-2">
        <div className="flex items-center gap-2 text-xs flex-wrap" style={{ color: 'var(--text-dim)' }}>
          <span>{agg.totalScans} Scan{agg.totalScans !== 1 ? 's' : ''}</span>
          {agg.activeScans > 0 && <span style={{ color: 'var(--tone-active)' }}>{agg.activeScans} aktiv</span>}
          {agg.failedScans > 0 && <span style={{ color: 'var(--tone-danger)' }}>{agg.failedScans} fehlgeschlagen</span>}
          {agg.lastScanAt && <span>· Zuletzt {formatDate(agg.lastScanAt)}</span>}
        </div>
        <Link href={`/scans/${group.key}`} onClick={e => e.stopPropagation()}
          className="text-xs font-medium px-3 py-1.5 rounded-md transition-colors"
          style={{ color: 'var(--text-muted)', border: '1px solid var(--border-muted)' }}>
          Öffnen →
        </Link>
      </div>
    </div>
  );
}

export default function ScansPage() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [loading, setLoading] = useState(true);
  const [orders, setOrders] = useState<OrderListItem[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [filter, setFilter] = useState<Filter>('all');
  const [search, setSearch] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoggedIn()) { router.replace('/login'); return; }
    setReady(true);
  }, [router]);

  const fetchData = useCallback(async () => {
    try {
      const [oRes, sRes] = await Promise.all([listOrders(), listSubscriptions()]);
      if (oRes.success && oRes.data) setOrders(oRes.data.orders);
      else setError(oRes.error || 'Fehler');
      if (sRes.success && sRes.data) setSubscriptions(sRes.data.subscriptions);
    } catch { setError('API nicht erreichbar'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { if (ready) fetchData(); }, [ready, fetchData]);

  const groups = groupOrders(orders, subscriptions, new Map());
  const filtered = groups
    .filter(g => groupMatchesFilter(g, filter))
    .filter(g => !search || g.title.toLowerCase().includes(search.toLowerCase()) || g.domains.some(d => d.toLowerCase().includes(search.toLowerCase())));

  const counts = {
    all: groups.length,
    active: groups.filter(g => g.aggregates.activeScans > 0).length,
    done: groups.filter(g => g.aggregates.doneScans > 0).length,
    failed: groups.filter(g => g.aggregates.failedScans > 0).length,
  };

  if (!ready) return null;

  return (
    <div className="px-4 py-6 md:px-8 max-w-5xl mx-auto space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <h1 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>Meine Scans</h1>
        <Link href="/scan/new"
          className="px-4 py-2 rounded-lg text-sm font-semibold transition-all min-h-[44px] flex items-center"
          style={{ backgroundColor: 'var(--tone-active)', color: 'var(--slate)' }}>
          + Neuer Scan
        </Link>
      </div>

      {/* Filter-Chips */}
      <div className="flex items-center gap-2 flex-wrap">
        {([['all', 'Alle', counts.all], ['active', 'Aktiv', counts.active], ['done', 'Fertig', counts.done], ['failed', 'Fehler', counts.failed]] as [Filter, string, number][]).map(([key, label, count]) => (
          <button key={key} onClick={() => setFilter(key)}
            className="px-3 py-1.5 rounded-full text-sm font-medium transition-colors"
            style={{
              color: filter === key ? 'var(--tone-active)' : 'var(--text-dim)',
              backgroundColor: filter === key ? 'color-mix(in srgb, var(--tone-active) 12%, transparent)' : 'transparent',
              border: `1px solid ${filter === key ? 'color-mix(in srgb, var(--tone-active) 30%, transparent)' : 'var(--border-muted)'}`,
            }}>
            {label} ({count})
          </button>
        ))}
        <input type="text" value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Domain suchen…" aria-label="Domain suchen"
          className="ml-auto text-sm px-3 py-1.5 rounded-lg max-w-[200px]"
          style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border-muted)', color: 'var(--text)' }} />
      </div>

      {error && (
        <StateView variant="error" title="Fehler beim Laden"
          description={error}
          actions={[{ label: 'Erneut versuchen', onClick: () => { setError(null); setLoading(true); fetchData(); } }]} />
      )}

      {loading && !error && <SkeletonList rows={5} />}

      {!loading && !error && groups.length === 0 && (
        <StateView variant="empty" title="Noch keine Scans"
          description="Starten Sie Ihren ersten Scan, um Ihre IT-Infrastruktur zu prüfen."
          actions={[
            { label: 'Neuer Scan', href: '/scan/new', variant: 'primary' },
            { label: 'Abo erstellen', href: '/subscribe', variant: 'secondary' },
          ]} />
      )}

      {!loading && !error && groups.length > 0 && filtered.length === 0 && (
        <StateView variant="info" title="Keine Scans für diesen Filter"
          description="Probieren Sie einen anderen Filter oder suchen Sie nach einer anderen Domain."
          actions={[{ label: 'Filter zurücksetzen', onClick: () => { setFilter('all'); setSearch(''); } }]} />
      )}

      {!loading && filtered.length > 0 && (
        <div className="space-y-3">
          {filtered.map(g => <ScanGroupCard key={g.key} group={g} />)}
        </div>
      )}
    </div>
  );
}
