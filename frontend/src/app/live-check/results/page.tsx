'use client';

// ── SofortScan: Ergebnis-Dashboard (Screen 3 + 4) ────────────────
// Route: /live-check/results?target=example.com
// VEC-366 — UX nach VEC-365 §3/§4/§5

import { useEffect, useRef, useState, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { isLoggedIn } from '@/lib/auth';

import CheckTile from '@/components/ds/CheckTile';
import LiveCheckProgress from '@/components/ds/LiveCheckProgress';
import CTAStaircase from '@/components/ds/CTAStaircase';
import StateView from '@/components/ds/StateView';
import SeverityCounts from '@/components/SeverityCounts';
import SeverityDrilldown from '@/components/ds/SeverityDrilldown';

import {
  fetchModules,
  runModule,
  runPool,
  CLIENT_CONCURRENCY,
  overallStatus,
  statusScore,
  GROUP_LABELS,
  GROUP_ORDER,
  extractDetail,
  type CheckModule,
  type CheckResult,
  type CheckGroup,
  type CheckStatus,
} from '@/lib/liveCheck';

// ---------------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------------

function ZapIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  );
}

function PassBigIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}
function WarnBigIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M12 9v4" /><path d="M12 17h.01" />
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
    </svg>
  );
}
function FailBigIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="12" cy="12" r="9" /><path d="m15 9-6 6" /><path d="m9 9 6 6" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// useLiveCheck hook
// ---------------------------------------------------------------------------

type Phase = 'init' | 'running' | 'done' | 'aborted' | 'error';

function useLiveCheck(target: string) {
  const [modules, setModules] = useState<CheckModule[]>([]);
  const [results, setResults] = useState<Map<string, CheckResult>>(new Map());
  const [phase, setPhase] = useState<Phase>('init');
  const abortRef = useRef<AbortController | null>(null);
  const startedRef = useRef(false);

  const abort = useCallback(() => {
    abortRef.current?.abort();
    setPhase('aborted');
  }, []);

  useEffect(() => {
    if (!target || startedRef.current) return;
    startedRef.current = true;

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    async function run() {
      let mods: CheckModule[];
      try {
        mods = await fetchModules();
      } catch {
        if (!ctrl.signal.aborted) setPhase('error');
        return;
      }

      if (ctrl.signal.aborted) return;

      setModules(mods);
      setPhase('running');

      // Init all as 'running'
      setResults(new Map(mods.map(m => [m.key, { ...m, status: 'running' as CheckStatus, summary: 'Läuft…' }])));

      // Global 60s timeout
      const globalTimer = setTimeout(() => ctrl.abort(), 60_000);

      // Worker-Pool statt allSettled über alle Module: höchstens
      // CLIENT_CONCURRENCY (= Server-Cap 4) Modul-Aufrufe gleichzeitig, damit
      // die übrigen nicht sofort in 429 too_many_concurrent laufen (VEC-381).
      await runPool(mods, CLIENT_CONCURRENCY, async (m) => {
        if (ctrl.signal.aborted) return;
        try {
          const r = await runModule(m.key, target, ctrl.signal);
          if (!ctrl.signal.aborted) {
            setResults(prev => {
              const next = new Map(prev);
              next.set(m.key, { ...m, ...r });
              return next;
            });
          }
        } catch {
          if (!ctrl.signal.aborted) {
            setResults(prev => {
              const next = new Map(prev);
              next.set(m.key, { ...m, status: 'error', summary: 'Nicht verfügbar' });
              return next;
            });
          }
        }
      });

      clearTimeout(globalTimer);

      if (!ctrl.signal.aborted) {
        setPhase('done');
      } else {
        setPhase('aborted');
      }
    }

    run();

    return () => {
      ctrl.abort();
    };
  }, [target]);

  const done = Array.from(results.values()).filter(r => !['running', 'pending'].includes(r.status)).length;
  const total = modules.length;

  return { modules, results, phase, done, total, abort };
}

// ---------------------------------------------------------------------------
// Derived severity counts (for SeverityCounts component)
// ---------------------------------------------------------------------------

function buildSeverityCounts(results: Map<string, CheckResult>): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const r of results.values()) {
    if (r.status === 'fail') counts['HIGH'] = (counts['HIGH'] ?? 0) + 1;
    else if (r.status === 'warn') counts['MEDIUM'] = (counts['MEDIUM'] ?? 0) + 1;
    else if (r.status === 'pass') counts['PASS'] = (counts['PASS'] ?? 0) + 1;
  }
  return counts;
}

// ---------------------------------------------------------------------------
// Detail-Extraktion (`extractDetail`) lebt jetzt zentral in `@/lib/liveCheck`
// (VEC-413) — eine Wahrheit für Status- UND Detail-Mapping gegen die reale
// web-check-2.1.9-Antwort. Vorher war sie hier dupliziert und gegen vermutete
// Feldnamen geschrieben (= wiederkehrender Bug, vgl. VEC-411).
// ---------------------------------------------------------------------------
// Screenshot rendering
// ---------------------------------------------------------------------------

function ScreenshotSection({ result }: { result: CheckResult }) {
  const r = result.detail as Record<string, unknown> | null;
  if (!r) return null;

  // web-check 2.1.9 liefert das Bild als ROHES Base64 in `image` (kein data:-URI,
  // VEC-413) — ohne `data:image/png;base64,`-Präfix rendert <img> nichts. Bereits
  // präfigierte data:-URIs bleiben unverändert; externe http(s)-URLs würden ohnehin
  // an CSP img-src 'self' data: scheitern → nicht inline rendern.
  const raw: string | null =
    typeof r.image === 'string' && r.image.trim() !== '' ? r.image
    : typeof r.screenshot === 'string' && r.screenshot.trim() !== '' ? r.screenshot
    : null;
  const src: string | null =
    raw === null ? null
    : /^data:/i.test(raw) ? raw
    : /^https?:\/\//i.test(raw) ? null
    : `data:image/png;base64,${raw}`;

  if (!src) {
    return (
      <div className="mt-8">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-3">Snapshot</h2>
        <StateView variant="info" title="Screenshot nicht verfügbar" description="Kein Screenshot wurde erstellt." />
      </div>
    );
  }

  return (
    <div className="mt-8">
      <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-3">Snapshot</h2>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={src}
        alt="Screenshot"
        onError={e => { (e.currentTarget as HTMLImageElement).style.display = 'none'; }}
        className="rounded-lg overflow-hidden border border-slate-700 w-full max-h-64 object-cover object-top"
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function LiveCheckResultsPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const target = searchParams.get('target') ?? '';

  const { modules, results, phase, done, total, abort } = useLiveCheck(target);

  // "Alle aufklappen" pro Gruppe (VEC-395 §4). Wert übersteuert lokalen
  // CheckTile-State via forceExpanded; undefined = Tile entscheidet selbst.
  const [groupAllExpanded, setGroupAllExpanded] = useState<Map<CheckGroup, boolean>>(new Map());

  // Severity-Drilldown (VEC-399): Klick auf einen Befund expandiert die
  // zugehörige Tile gezielt (übersteuert groupAllExpanded) + scrollt sie an.
  const [keyExpanded, setKeyExpanded] = useState<Map<string, boolean>>(new Map());

  // Lokaler Expand-State pro Tile (VEC-415): treibt den Grid-col-span-Wrapper,
  // damit die aufgeklappte Kachel beide Spalten überspannt.
  const [tileLocalExpanded, setTileLocalExpanded] = useState<Map<string, boolean>>(new Map());

  const onDrilldownSelect = useCallback((key: string) => {
    setKeyExpanded(prev => new Map(prev).set(key, true));
    // Kurze Verzögerung, damit die Tile vor dem Scroll aufgeklappt gerendert ist.
    setTimeout(() => {
      document.getElementById(`tile-${key}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);
  }, []);

  // Auth guard — must be logged in to access live-check
  useEffect(() => {
    if (!isLoggedIn()) {
      router.replace('/login');
    }
  }, [router]);

  // Redirect to input if no target
  useEffect(() => {
    if (!target) router.replace('/live-check');
  }, [target, router]);

  if (!target) return null;

  // ── Phase: init / loading modules ────────────────────────────
  if (phase === 'init') {
    return (
      <div className="max-w-2xl mx-auto px-4 pt-10">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-5 h-5 rounded-full border-2 border-teal-500 border-t-transparent ds-spin" aria-hidden />
          <span className="text-sm text-slate-400">Sofort-Check wird vorbereitet…</span>
        </div>
      </div>
    );
  }

  // ── Phase: error ──────────────────────────────────────────────
  if (phase === 'error') {
    return (
      <div className="max-w-2xl mx-auto px-4 pt-10">
        <StateView
          variant="error"
          title="Sofort-Check nicht verfügbar"
          description="Die Checks konnten nicht gestartet werden. Bitte versuchen Sie es erneut."
          actions={[{ label: 'Neuer Sofort-Check', href: '/live-check' }]}
        />
      </div>
    );
  }

  const resultsList = Array.from(results.values());
  const overall = overallStatus(resultsList.filter(r => ['pass', 'warn', 'fail'].includes(r.status)));
  const severityCounts = buildSeverityCounts(results);
  const isRunning = phase === 'running';

  const OVERALL_META = {
    pass: { color: '#10B981', Icon: PassBigIcon, headline: 'Gute Basislage — Details unten' },
    warn: { color: '#F59E0B', Icon: WarnBigIcon, headline: `Handlungsbedarf` },
    fail: { color: '#EF4444', Icon: FailBigIcon, headline: 'Kritische Lücken gefunden' },
  };

  // Group results by category, sort fail first within each group
  const grouped = new Map<CheckGroup, CheckResult[]>();
  for (const g of GROUP_ORDER) grouped.set(g, []);
  for (const r of resultsList) {
    grouped.get(r.group as CheckGroup)?.push(r);
  }
  for (const [, arr] of grouped) {
    arr.sort((a, b) => statusScore(a.status) - statusScore(b.status));
  }

  // Screenshot module separate
  const screenshotResult = results.get('screenshot');

  return (
    <div className="max-w-2xl mx-auto px-4 pt-8 pb-16">
      {/* Header row */}
      <div className="flex items-start justify-between gap-4 mb-6">
        <div>
          <h1 className="text-xl font-bold text-slate-100 truncate">{target}</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Sofort-Check ·{' '}
            {new Date().toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric' })}
            {' '}
            {new Date().toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {isRunning && (
            <button
              type="button"
              onClick={abort}
              className="px-3 py-1.5 rounded-lg text-xs border text-slate-400 hover:text-slate-200 transition-colors min-h-[36px]"
              style={{ borderColor: 'var(--border-muted)' }}
            >
              Abbrechen
            </button>
          )}
          <Link
            href="/live-check"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs border transition-colors min-h-[36px]"
            style={{ color: 'var(--text-muted)', borderColor: 'var(--border-muted)' }}
          >
            <ZapIcon />
            Neuer Sofort-Check
          </Link>
        </div>
      </div>

      {/* Progress bar (while running) */}
      {isRunning && total > 0 && (
        <LiveCheckProgress done={done} total={total} className="mb-6" />
      )}

      {/* Aborted banner */}
      {phase === 'aborted' && (
        <div className="mb-6 px-4 py-3 rounded-lg text-sm text-amber-300 border border-amber-400/20"
          style={{ background: 'rgba(245,158,11,0.08)' }}>
          Einige Checks wurden abgebrochen. Verfügbare Ergebnisse werden angezeigt.
        </div>
      )}

      {/* Hero summary (only when we have results) */}
      {overall && (() => {
        const meta = OVERALL_META[overall];
        const OverallIcon = meta.Icon;
        return (
          <div key="hero" className="mb-8 flex items-center gap-4 p-5 rounded-xl border"
            style={{
              background: `color-mix(in srgb, ${meta.color} 6%, var(--slate-light))`,
              borderColor: `color-mix(in srgb, ${meta.color} 24%, transparent)`,
            }}>
            <span className="shrink-0 w-12 h-12 rounded-full flex items-center justify-center"
              style={{
                color: meta.color,
                background: `color-mix(in srgb, ${meta.color} 14%, transparent)`,
              }}>
              <OverallIcon />
            </span>
            <div>
              <p className="font-semibold text-slate-100">{meta.headline}</p>
              <div className="mt-1">
                <SeverityCounts counts={severityCounts} />
              </div>
            </div>
          </div>
        );
      })()}

      {/* Severity-Drilldown (VEC-399): welche Checks machen H/M aus.
          Nur bei abgeschlossenem Scan — während running sind Counts unvollständig. */}
      {(phase === 'done' || phase === 'aborted') && (
        <SeverityDrilldown results={resultsList} onSelect={onDrilldownSelect} />
      )}

      {/* Check sections by group */}
      <div className="space-y-8">
        {GROUP_ORDER.map(group => {
          const items = grouped.get(group) ?? [];
          if (items.length === 0) return null;
          // Hide screenshot from main grid (rendered separately)
          const displayItems = group === 'info' ? items.filter(r => r.key !== 'screenshot') : items;
          if (displayItems.length === 0) return null;

          // Detail einmal pro Item ableiten; bestimmt auch, ob "Alle aufklappen" sinnvoll ist.
          const itemDetails = displayItems.map(r => ({ result: r, ...extractDetail(r) }));
          const groupHasDetail = itemDetails.some(d => d.detail.length > 0);
          const allExpanded = groupAllExpanded.get(group) === true;

          return (
            <section key={group}>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  {GROUP_LABELS[group]}
                </h2>
                {groupHasDetail && (
                  <button
                    type="button"
                    onClick={() => setGroupAllExpanded(prev => {
                      const next = new Map(prev);
                      next.set(group, !allExpanded);
                      return next;
                    })}
                    className="text-xs text-slate-600 hover:text-slate-400 transition-colors"
                    aria-expanded={allExpanded}
                  >
                    {allExpanded ? 'Alle einklappen' : 'Alle aufklappen'}
                  </button>
                )}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 items-start">
                {itemDetails.map(({ result: r, detail, hiddenCount }) => {
                  // Aufgeklappte Kachel überspannt beide Grid-Spalten (sm+):
                  // lokaler Toggle ODER gezielter Drilldown ODER "Alle aufklappen".
                  const isExpanded =
                    tileLocalExpanded.get(r.key) === true ||
                    keyExpanded.get(r.key) === true ||
                    (groupAllExpanded.has(group) ? allExpanded : false);
                  return (
                    <div key={r.key} className={isExpanded ? 'sm:col-span-2' : ''}>
                      <CheckTile
                        tileId={r.key}
                        label={r.label}
                        status={r.status}
                        summary={r.summary}
                        detail={detail}
                        hiddenCount={hiddenCount}
                        forceExpanded={
                          keyExpanded.has(r.key)
                            ? keyExpanded.get(r.key)
                            : groupAllExpanded.has(group) ? allExpanded : undefined
                        }
                        onExpandChange={(exp) =>
                          setTileLocalExpanded(prev => new Map(prev).set(r.key, exp))
                        }
                      />
                    </div>
                  );
                })}
              </div>
            </section>
          );
        })}
      </div>

      {/* Screenshot section */}
      {screenshotResult && <ScreenshotSection result={screenshotResult} />}

      {/* CTA Staircase — only when scan is done */}
      {(phase === 'done' || phase === 'aborted') && (
        <CTAStaircase domain={target} />
      )}

      {/* Disclaimer */}
      {(phase === 'done' || phase === 'aborted') && (
        <p className="mt-6 text-xs text-slate-600 text-center">
          Momentaufnahme öffentlich erreichbarer Dienste. Kein Penetrationstest.
          Zeitstempel: {new Date().toLocaleString('de-DE')}.
        </p>
      )}
    </div>
  );
}
