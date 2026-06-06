'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { listOrders, deleteOrderPermanent, listSubscriptions, getSubscriptionPosture, OrderListItem, Subscription, SubscriptionPosture } from '@/lib/api';
import { isLoggedIn, isAdmin } from '@/lib/auth';
import SeverityCounts from '@/components/SeverityCounts';
import { groupOrders, OrderGroup } from '@/lib/grouping';
import StateView from '@/components/ds/StateView';
import StatusChip from '@/components/ds/StatusChip';
import ConfirmDialog from '@/components/ds/ConfirmDialog';
import { SkeletonCards, SkeletonList } from '@/components/ds/Skeleton';


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

// H10: Risk-/Score-Farben aus Ton-Tokens (globals.css) statt Hex.
const RISK_TONE: Record<string, string> = {
  CRITICAL: 'var(--tone-danger)',
  HIGH:     'var(--tone-warn)',
  MEDIUM:   'var(--tone-info)',
  LOW:      'var(--tone-success)',
};

function scoreColor(score: number): string {
  if (score >= 80) return 'var(--tone-success)';
  if (score >= 60) return 'var(--tone-warn)';
  return 'var(--tone-danger)';
}

function trendGlyph(dir: SubscriptionPosture['trendDirection']): string {
  return dir === 'improving' ? '↗' : dir === 'degrading' ? '↘' : dir === 'stable' ? '→' : '';
}

const RUNNING_STATUSES = ['scanning', 'queued', 'passive_intel', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_phase3', 'report_generating'];
const DONE_STATUSES = ['report_complete', 'delivered'];
const WAITING_STATUSES = ['pending_target_review', 'scan-pending', 'scan_pending', 'verified', 'approved', 'pending_review', 'scan_complete', 'created'];

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

// ── Posture-Snapshot-Aggregation (§5.1) ──────────────────────────
// Bevorzugt deduplizierte open-Findings aus den Subscription-Postures;
// fällt für Einzelscan-Kunden (ohne Abo-Aggregation) auf die Severity
// des jeweils jüngsten fertigen Scans pro Domain zurück.
const SEV_KEYS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

interface PostureSnapshot {
  score: number | null;
  trend: SubscriptionPosture['trendDirection'];
  severity: Record<string, number>;
  highestRisk: string | null;
  domains: number;
  totalScans: number;
  activeScans: number;
}

function buildSnapshot(
  orders: OrderListItem[],
  postures: Map<string, SubscriptionPosture | null>,
): PostureSnapshot {
  const severity: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  let worstScore: number | null = null;
  let worstTrend: SubscriptionPosture['trendDirection'] = 'unknown';
  let hasPosture = false;

  for (const p of postures.values()) {
    if (!p) continue;
    hasPosture = true;
    if (p.postureScore != null && (worstScore == null || p.postureScore < worstScore)) {
      worstScore = p.postureScore;
      worstTrend = p.trendDirection;
    }
    const open = p.severityCounts?.open;
    if (open) for (const k of SEV_KEYS) severity[k] += open[k] ?? 0;
  }

  // Fallback: jüngster fertiger Scan pro Domain (kein Doppelzählen von Re-Scans).
  if (!hasPosture) {
    const latestByDomain = new Map<string, OrderListItem>();
    for (const o of orders) {
      if (!DONE_STATUSES.includes(o.status)) continue;
      const prev = latestByDomain.get(o.domain);
      if (!prev || new Date(o.createdAt) > new Date(prev.createdAt)) latestByDomain.set(o.domain, o);
    }
    for (const o of latestByDomain.values()) {
      if (o.severityCounts) for (const k of SEV_KEYS) severity[k] += o.severityCounts[k] ?? 0;
    }
  }

  const highestRisk = severity.CRITICAL > 0 ? 'CRITICAL'
    : severity.HIGH > 0 ? 'HIGH'
    : severity.MEDIUM > 0 ? 'MEDIUM'
    : severity.LOW > 0 ? 'LOW' : null;

  return {
    score: worstScore != null ? Math.round(worstScore) : null,
    trend: worstTrend,
    severity,
    highestRisk,
    domains: new Set(orders.map(o => o.domain)).size,
    totalScans: orders.length,
    activeScans: orders.filter(o => RUNNING_STATUSES.includes(o.status)).length,
  };
}

// ── „Nächster Schritt"-Card (Anti-Sackgasse, §5.1) ───────────────
// Liefert immer GENAU eine sinnvollste Aktion (Goal-Gradient).
interface NextStep {
  variant: 'empty' | 'info' | 'denied';
  warn?: boolean;
  title: string;
  description: string;
  actionLabel: string;
  href: string;
}

function computeNextStep(
  orders: OrderListItem[],
  completedWebchecks: OrderListItem[],
  hasActiveSub: boolean,
): NextStep {
  // 1. Blockierend: eine Domain wartet auf Bestätigung durch den Kunden.
  const verify = orders.find(o => o.status === 'verification_pending');
  if (verify) {
    return {
      variant: 'denied', warn: true,
      title: 'Domain bestätigen',
      description: `Bestätigen Sie ${verify.domain}, damit der Scan starten kann.`,
      actionLabel: 'Jetzt bestätigen', href: `/scan/${verify.id}`,
    };
  }

  // 2. Erstnutzer: kein einziger Scan → großer Einstiegs-Anker.
  if (orders.length === 0) {
    return {
      variant: 'empty',
      title: 'Ersten Scan starten',
      description: 'Ein kostenloser WebCheck zeigt Ihnen in wenigen Minuten, wo Ihr Webauftritt steht.',
      actionLabel: 'Scan starten', href: '/scan/new',
    };
  }

  // 3. Zustand des jüngsten Auftrags treibt den nächsten Schritt.
  const recent = [...orders].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  )[0];
  const s = recent.status;

  if (DONE_STATUSES.includes(s)) {
    // Upsell vor Bericht, solange der Kunde nur WebCheck ohne Abo hat.
    if (!hasActiveSub && completedWebchecks.length > 0) {
      return {
        variant: 'info',
        title: 'Tiefer gehen',
        description: 'Ein Perimeter-Scan deckt Netzwerk, Subdomains und DSGVO-Konformität auf.',
        actionLabel: 'Perimeter freischalten', href: '/subscribe?package=perimeter',
      };
    }
    return {
      variant: 'info',
      title: 'Bericht ansehen',
      description: `Ihr Bericht für ${recent.domain} ist fertig.`,
      actionLabel: 'Bericht öffnen', href: `/scan/${recent.id}`,
    };
  }

  if (RUNNING_STATUSES.includes(s)) {
    return {
      variant: 'info',
      title: 'Scan läuft',
      description: `${recent.domain} wird gerade geprüft — wir benachrichtigen Sie, sobald der Bericht fertig ist.`,
      actionLabel: 'Fortschritt ansehen', href: `/scan/${recent.id}`,
    };
  }

  if (['failed', 'rejected', 'cancelled'].includes(s)) {
    return {
      variant: 'denied', warn: true,
      title: 'Scan wiederholen',
      description: `Der letzte Scan für ${recent.domain} ist nicht durchgelaufen. Starten Sie ihn neu.`,
      actionLabel: 'Neuer Scan', href: '/scan/new',
    };
  }

  if (WAITING_STATUSES.includes(s)) {
    return {
      variant: 'info',
      title: 'In Bearbeitung',
      description: `${recent.domain} ist in der Warteschlange — wir kümmern uns darum.`,
      actionLabel: 'Status ansehen', href: `/scan/${recent.id}`,
    };
  }

  // 4. Fallback: alles erledigt.
  return {
    variant: 'empty',
    title: 'Neuen Scan starten',
    description: 'Alles erledigt. Starten Sie den nächsten Scan, wann immer Sie bereit sind.',
    actionLabel: 'Neuer Scan', href: '/scan/new',
  };
}

export default function Dashboard() {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [admin, setAdmin] = useState(false);

  const [orders, setOrders] = useState<OrderListItem[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [postures, setPostures] = useState<Map<string, SubscriptionPosture | null>>(new Map());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<StatusFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  // H7: ConfirmDialog statt nativem confirm() beim Löschen.
  const [pendingDelete, setPendingDelete] = useState<OrderListItem | null>(null);
  const [deleting, setDeleting] = useState(false);
  const PAGE_SIZE = 20;

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
        const subs = subsRes.data.subscriptions;
        setSubscriptions(subs);
        // PR-Posture: parallel alle Subscription-Postures laden — fuer
        // dedup-basierte Severity-Counts in der GroupCard. Ein 404 ist ok
        // (Subscription hat noch keine Aggregation gehabt).
        const postureMap = new Map<string, SubscriptionPosture | null>();
        await Promise.all(subs.map(async (s) => {
          try {
            const pr = await getSubscriptionPosture(s.id);
            postureMap.set(s.id, pr.success && pr.data ? pr.data : null);
          } catch { postureMap.set(s.id, null); }
        }));
        setPostures(postureMap);
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

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setDeleting(true);
    try {
      const res = await deleteOrderPermanent(pendingDelete.id);
      if (res.success) {
        setOrders((prev) => prev.filter((o) => o.id !== pendingDelete.id));
        setPendingDelete(null);
      } else {
        setError(res.error || 'Fehler beim Löschen');
      }
    } catch {
      setError('Fehler beim Löschen');
    } finally {
      setDeleting(false);
    }
  };

  const groups = groupOrders(orders, subscriptions, postures);
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

  // ── Onboarding-/Posture-Logik (VEC-293 + §5.1) ───────────────────
  const hasActiveSub = subscriptions.length > 0;
  const completedWebchecks = orders.filter(
    o => ['webcheck', 'basic'].includes(o.package ?? '') && o.status === 'report_complete'
  );
  const snapshot = buildSnapshot(orders, postures);
  const nextStep = computeNextStep(orders, completedWebchecks, hasActiveSub);
  const hasScans = orders.length > 0;

  if (!ready) return null;

  return (
    <main className="flex-1 px-4 py-6 md:px-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header: Titel + Primär-CTA rechts (Fitts) */}
        <div className="flex items-center justify-between gap-3">
          <h1 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>Übersicht</h1>
          <Link
            href="/scan/new"
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold transition-all min-h-[40px]"
            style={{ backgroundColor: 'var(--tone-active)', color: 'var(--slate)' }}
          >
            <span className="text-base leading-none">+</span> Neuer Scan
          </Link>
        </div>

        {error && (
          <div
            className="rounded-lg px-4 py-3 text-sm"
            style={{
              color: 'var(--tone-danger)',
              backgroundColor: 'color-mix(in srgb, var(--tone-danger) 12%, transparent)',
              border: '1px solid color-mix(in srgb, var(--tone-danger) 28%, transparent)',
            }}
          >{error}</div>
        )}

        {/* H9: Skeleton beim Laden statt "Lade…"-Text */}
        {loading && (
          <>
            <SkeletonCards count={4} />
            <SkeletonList rows={3} />
          </>
        )}

        {/* Erstnutzer (0 Scans): EIN großer Anti-Sackgassen-Anker, kein Zweit-CTA (H2) */}
        {!loading && !hasScans && (
          <StateView
            variant={nextStep.variant}
            title={nextStep.title}
            description={nextStep.description}
            actions={[{ label: nextStep.actionLabel, href: nextStep.href, variant: 'primary' }]}
          >
            <Link href="/subscribe" className="text-sm mt-1 inline-block" style={{ color: 'var(--text-muted)' }}>
              Alle Pakete ansehen →
            </Link>
          </StateView>
        )}

        {/* Posture-Snapshot + Nächster Schritt */}
        {!loading && hasScans && (
          <div className="grid gap-4 md:grid-cols-3">
            <div className="md:col-span-2">
              <PostureSnapshot snapshot={snapshot} />
            </div>
            <NextStepCard step={nextStep} />
          </div>
        )}

        {/* ── Letzte Scans ──────────────────────────────────────────── */}
        {!loading && hasScans && (
          <section className="space-y-4">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <h2 className="text-sm font-semibold" style={{ color: 'var(--text)' }}>Letzte Scans</h2>
              {lastUpdate && (
                <span className="text-xs" style={{ color: 'var(--text-dim)' }}>
                  Aktualisiert {lastUpdate.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })} Uhr
                </span>
              )}
            </div>

            {/* Filter pills */}
            <div className="flex items-center gap-2 flex-wrap">
              {([
                ['all', 'Alle', counts.all],
                ['subscription', 'Abo', counts.subscription],
                ['domain', 'Einzelscan', counts.domain],
                ['active', 'Aktiv', counts.active],
                ['done', 'Fertig', counts.done],
                ['failed', 'Fehlgeschlagen', counts.failed],
              ] as [StatusFilter, string, number][]).map(([key, label, count]) => {
                const selected = filter === key;
                return (
                  <button key={key} onClick={() => setFilter(key)}
                    className="px-3 py-1.5 rounded-full text-sm font-medium transition-colors"
                    style={selected
                      ? { color: 'var(--tone-active)', backgroundColor: 'color-mix(in srgb, var(--tone-active) 15%, transparent)', boxShadow: 'inset 0 0 0 1px color-mix(in srgb, var(--tone-active) 30%, transparent)' }
                      : { color: 'var(--text-dim)' }}
                  >{label} ({count})</button>
                );
              })}
            </div>

            {/* Search */}
            <input
              type="text"
              value={searchQuery}
              onChange={e => { setSearchQuery(e.target.value); setPage(1); }}
              placeholder="Domain suchen..."
              className="w-full sm:max-w-xs rounded-lg px-4 py-2.5 text-sm focus:outline-none"
              style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border-muted)', color: 'var(--text)' }}
            />

            {/* Group cards */}
            {filteredGroups.length > 0 && (
              <div className="space-y-4">
                {paginatedGroups.map((group) => (
                  <GroupCard key={group.key} group={group} admin={admin} />
                ))}

                {totalPages > 1 && (
                  <div className="flex items-center justify-center gap-2 pt-4">
                    <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
                      className="text-xs px-3 py-1.5 rounded-md disabled:opacity-30 transition-colors"
                      style={{ color: 'var(--text-muted)', border: '1px solid var(--border-subtle)' }}>Zurück</button>
                    <span className="text-xs" style={{ color: 'var(--text-dim)' }}>Seite {page} von {totalPages}</span>
                    <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
                      className="text-xs px-3 py-1.5 rounded-md disabled:opacity-30 transition-colors"
                      style={{ color: 'var(--text-muted)', border: '1px solid var(--border-subtle)' }}>Weiter</button>
                  </div>
                )}
              </div>
            )}

            {groups.length > 0 && filteredGroups.length === 0 && (
              <StateView
                variant="empty"
                title="Keine Treffer"
                description="Mit diesem Filter oder Suchbegriff gibt es keine Scans."
                actions={[{ label: 'Filter zurücksetzen', onClick: () => { setFilter('all'); setSearchQuery(''); }, variant: 'secondary' }]}
              />
            )}
          </section>
        )}

        {/* Admin: Delete legacy individual orders inline */}
        {!loading && admin && groups.some(g => g.kind === 'domain') && (
          <details className="text-xs" style={{ color: 'var(--text-dim)' }}>
            <summary className="cursor-pointer hover:opacity-80">Admin: Einzelne Scans verwalten</summary>
            <div className="mt-2 space-y-1 max-h-64 overflow-auto pr-2">
              {orders.filter(o => !o.subscriptionId).map(o => (
                <div key={o.id} className="flex items-center justify-between gap-2 py-1" style={{ borderBottom: '1px solid var(--border-muted)' }}>
                  <span className="font-mono truncate" style={{ color: 'var(--text-muted)' }}>{o.domain} &middot; {o.id.slice(0, 8)}</span>
                  <button onClick={() => setPendingDelete(o)} style={{ color: 'var(--tone-danger)' }} className="hover:opacity-80">Löschen</button>
                </div>
              ))}
            </div>
          </details>
        )}
      </div>

      {/* H7: Bestätigungs-Modal beim Löschen */}
      <ConfirmDialog
        open={pendingDelete !== null}
        destructive
        busy={deleting}
        title="Order endgültig löschen?"
        description={pendingDelete
          ? `Die Order für ${pendingDelete.domain} wird unwiderruflich gelöscht. Dies kann nicht rückgängig gemacht werden.`
          : ''}
        confirmLabel="Endgültig löschen"
        onConfirm={confirmDelete}
        onCancel={() => { if (!deleting) setPendingDelete(null); }}
      />
    </main>
  );
}

// ────────────────────────────────────────────────────────────
// Posture-Snapshot — größtes Element, „Wie steht's um meine Sicherheit?"
// ────────────────────────────────────────────────────────────
function PostureSnapshot({ snapshot }: { snapshot: PostureSnapshot }) {
  const { score, trend, severity, highestRisk, domains, totalScans, activeScans } = snapshot;
  const headlineColor = score != null
    ? scoreColor(score)
    : highestRisk ? RISK_TONE[highestRisk] : 'var(--text-muted)';

  return (
    <div
      className="rounded-xl p-5 h-full"
      style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border-muted)' }}
    >
      <p className="text-[10px] uppercase tracking-wider mb-3" style={{ color: 'var(--text-dim)' }}>
        Sicherheitslage
      </p>

      <div className="flex items-end gap-4 flex-wrap">
        {/* Headline-Metrik: Posture-Score (mit Trend) oder Gesamtrisiko */}
        {score != null ? (
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-bold leading-none" style={{ color: headlineColor }}>{score}</span>
            <span className="text-sm font-medium" style={{ color: headlineColor }}>
              {trendGlyph(trend)} <span style={{ color: 'var(--text-dim)' }}>/ 100</span>
            </span>
          </div>
        ) : (
          <span className="text-3xl font-bold leading-none" style={{ color: headlineColor }}>
            {highestRisk ?? 'Sauber'}
          </span>
        )}

        {/* Severity-Aufschlüsselung in Klartext */}
        <div className="flex-1 min-w-[160px]">
          <SeverityBar severity={severity} />
          <p className="text-xs mt-1.5" style={{ color: 'var(--text-muted)' }}>
            {severity.CRITICAL > 0 && <span style={{ color: 'var(--tone-danger)' }}>{severity.CRITICAL} kritisch</span>}
            {severity.CRITICAL > 0 && (severity.HIGH + severity.MEDIUM + severity.LOW) > 0 && ' · '}
            {severity.HIGH > 0 && <span style={{ color: 'var(--tone-warn)' }}>{severity.HIGH} hoch</span>}
            {severity.HIGH > 0 && (severity.MEDIUM + severity.LOW) > 0 && ' · '}
            {severity.MEDIUM > 0 && <>{severity.MEDIUM} mittel</>}
            {severity.MEDIUM > 0 && severity.LOW > 0 && ' · '}
            {severity.LOW > 0 && <>{severity.LOW} niedrig</>}
            {(severity.CRITICAL + severity.HIGH + severity.MEDIUM + severity.LOW) === 0 && 'Keine offenen Schwachstellen'}
          </p>
        </div>
      </div>

      {/* Sekundäre Meta-Zeile */}
      <div className="flex items-center gap-1.5 text-xs mt-4 flex-wrap" style={{ color: 'var(--text-dim)' }}>
        <span>{domains} Domain{domains !== 1 ? 's' : ''}</span>
        <span>·</span>
        <span>{totalScans} Scan{totalScans !== 1 ? 's' : ''}</span>
        {activeScans > 0 && (
          <>
            <span>·</span>
            <span style={{ color: 'var(--tone-active)' }}>{activeScans} aktiv</span>
          </>
        )}
      </div>
    </div>
  );
}

// Proportionaler Severity-Balken (Farb-Unabhängigkeit: Klartext steht darunter).
function SeverityBar({ severity }: { severity: Record<string, number> }) {
  const segments = [
    { key: 'CRITICAL', color: 'var(--tone-danger)' },
    { key: 'HIGH', color: 'var(--tone-warn)' },
    { key: 'MEDIUM', color: 'var(--tone-info)' },
    { key: 'LOW', color: 'var(--tone-success)' },
  ];
  const total = segments.reduce((s, seg) => s + (severity[seg.key] || 0), 0);
  return (
    <div
      className="h-2 w-full rounded-full overflow-hidden flex"
      style={{ backgroundColor: 'var(--surface-inset)' }}
      aria-hidden
    >
      {total > 0 && segments.map(seg => {
        const v = severity[seg.key] || 0;
        if (v === 0) return null;
        return <div key={seg.key} style={{ width: `${(v / total) * 100}%`, backgroundColor: seg.color }} />;
      })}
    </div>
  );
}

// ────────────────────────────────────────────────────────────
// „Nächster Schritt"-Card — der eine Anti-Sackgassen-Anker (§5.1)
// ────────────────────────────────────────────────────────────
function NextStepCard({ step }: { step: NextStep }) {
  const accent = step.warn ? 'var(--tone-warn)' : 'var(--tone-active)';
  return (
    <div
      className="rounded-xl p-5 h-full flex flex-col"
      style={{
        backgroundColor: 'var(--surface)',
        border: `1px solid color-mix(in srgb, ${accent} 30%, transparent)`,
      }}
    >
      <p className="text-[10px] uppercase tracking-wider mb-2" style={{ color: accent }}>Nächster Schritt</p>
      <h3 className="text-base font-semibold" style={{ color: 'var(--text)' }}>{step.title}</h3>
      <p className="text-sm mt-1.5 flex-1" style={{ color: 'var(--text-muted)' }}>{step.description}</p>
      <Link
        href={step.href}
        className="mt-4 inline-flex items-center justify-center px-4 py-2.5 rounded-lg text-sm font-semibold transition-all min-h-[44px]"
        style={{ backgroundColor: accent, color: 'var(--slate)' }}
      >
        {step.actionLabel}
      </Link>
    </div>
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
  const totalSeverity = agg.severityCounts.CRITICAL + agg.severityCounts.HIGH + agg.severityCounts.MEDIUM + agg.severityCounts.LOW;
  const groupHref = `/scans/${group.key}`;

  return (
    <div
      className="rounded-lg p-5 transition-colors cursor-pointer"
      style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border-muted)' }}
      onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'var(--surface-2)'; }}
      onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'var(--surface)'; }}
      onClick={() => router.push(groupHref)}
    >
      {/* Header row */}
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-3 min-w-0 flex-wrap">
          <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded"
            style={group.kind === 'subscription'
              ? { color: 'var(--tone-active)', backgroundColor: 'color-mix(in srgb, var(--tone-active) 15%, transparent)' }
              : group.kind === 'order'
              ? { color: 'var(--tone-info)', backgroundColor: 'color-mix(in srgb, var(--tone-info) 15%, transparent)' }
              : { color: 'var(--text-muted)', backgroundColor: 'color-mix(in srgb, var(--text-muted) 15%, transparent)' }}
          >
            {group.kind === 'subscription' ? 'Abo' : group.kind === 'order' ? 'Multi-Target' : 'Einzelscans'}
          </span>
          <span className="font-semibold text-sm truncate" style={{ color: 'var(--text)' }}>{group.title}</span>
          <span className="text-xs truncate" style={{ color: 'var(--text-dim)' }}>{group.subtitle}</span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {/* PR-Posture: Score + Trend-Pfeil bei Subscription-Groups */}
          {agg.posture && agg.posture.postureScore != null && group.subscription && (() => {
            const ps = Math.round(agg.posture.postureScore);
            const col = scoreColor(ps);
            return (
              <Link
                href={`/subscription/${group.subscription.id}/posture`}
                onClick={(e) => e.stopPropagation()}
                className="text-xs font-bold px-2 py-0.5 rounded inline-flex items-center gap-1 hover:brightness-110"
                style={{ color: col, backgroundColor: `color-mix(in srgb, ${col} 15%, transparent)`, boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${col} 30%, transparent)` }}
                title={`Posture-Score ${ps} (open-Findings) — ${agg.posture.trendDirection}. Klick fuer Posture-Detail`}
              >
                <span>{ps}</span>
                <span className="text-[10px]">{trendGlyph(agg.posture.trendDirection)}</span>
              </Link>
            );
          })()}
          {agg.latestStatus && (
            <StatusChip status={agg.latestStatus} size="sm" />
          )}
        </div>
      </div>

      {/* Aggregated severity */}
      {totalSeverity > 0 && (
        <div className="mb-3">
          <SeverityCounts counts={agg.severityCounts} />
          {agg.posture && (
            <div className="text-[10px] mt-1" style={{ color: 'var(--text-dim)' }}>
              {agg.posture.severityCounts.total_open ?? 0} offen
              {(agg.posture.severityCounts.resolved_total ?? 0) > 0 &&
                ` · ${agg.posture.severityCounts.resolved_total} resolved`}
              {(agg.posture.severityCounts.regressed_total ?? 0) > 0 &&
                ` · ${agg.posture.severityCounts.regressed_total} regressed`}
              {(agg.posture.severityCounts.accepted_total ?? 0) > 0 &&
                ` · ${agg.posture.severityCounts.accepted_total} risk-accepted`}
            </div>
          )}
        </div>
      )}

      {/* Meta row */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap text-xs" style={{ color: 'var(--text-dim)' }}>
          {pkgLabel && (
            <>
              <span className="font-mono uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{pkgLabel}</span>
              <span>&middot;</span>
            </>
          )}
          {intervalLabel && (
            <><span>{intervalLabel}</span><span>&middot;</span></>
          )}
          <span>{agg.totalScans} Scan{agg.totalScans !== 1 ? 's' : ''}</span>
          {agg.activeScans > 0 && (
            <><span>&middot;</span><span style={{ color: 'var(--tone-info)' }}>{agg.activeScans} aktiv</span></>
          )}
          {agg.failedScans > 0 && (
            <><span>&middot;</span><span style={{ color: 'var(--tone-danger)' }}>{agg.failedScans} fehlgeschlagen</span></>
          )}
          {sub && (
            <>
              <span>&middot;</span>
              <span title="Verbleibende Re-Scans aus dem Abo-Kontingent">{sub.maxRescans - sub.rescansUsed}/{sub.maxRescans} Re-Scans</span>
            </>
          )}
          {agg.lastScanAt && (
            <><span>&middot;</span><span>Zuletzt {formatDate(agg.lastScanAt)}</span></>
          )}
          {!agg.lastScanAt && sub && (
            <span style={{ color: 'var(--text-muted)' }}>Noch keine Scans</span>
          )}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {admin && group.orders[0]?.email && <span className="text-[10px] hidden sm:inline" style={{ color: 'var(--text-dim)' }}>{group.orders[0].email}</span>}
          <Link href={groupHref} onClick={(e) => e.stopPropagation()}
            className="text-xs font-medium px-3 py-1.5 rounded-lg transition-colors"
            style={{ color: 'var(--text-muted)', backgroundColor: 'color-mix(in srgb, var(--text-muted) 8%, transparent)' }}>
            Öffnen →
          </Link>
        </div>
      </div>
    </div>
  );
}
