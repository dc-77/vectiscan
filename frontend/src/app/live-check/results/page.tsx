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

import {
  fetchModules,
  runModule,
  overallStatus,
  statusScore,
  GROUP_LABELS,
  GROUP_ORDER,
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

      await Promise.allSettled(
        mods.map(async (m) => {
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
        }),
      );

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
    else if (r.status === 'pass') counts['INFO'] = (counts['INFO'] ?? 0) + 1;
  }
  return counts;
}

// ---------------------------------------------------------------------------
// Detail line extraction (drives CheckTile progressive disclosure)
// ---------------------------------------------------------------------------

function extractDetailLines(result: CheckResult): string[] {
  if (!result.detail || typeof result.detail !== 'object' || Array.isArray(result.detail)) return [];
  const r = result.detail as Record<string, unknown>;
  const lines: string[] = [];

  switch (result.key) {
    case 'http-headers': {
      const missing = Array.isArray(r.missingHeaders) ? (r.missingHeaders as string[]) : [];
      missing.slice(0, 3).forEach(h => lines.push(`Fehlt: ${h}`));
      break;
    }
    case 'cookies': {
      const ins: unknown[] = Array.isArray(r.insecureCookies) ? r.insecureCookies
        : Array.isArray(r.unsecureCookies) ? r.unsecureCookies : [];
      ins.slice(0, 3).forEach(c => {
        const name = typeof c === 'object' && c !== null && 'name' in c
          ? (c as { name: string }).name : String(c);
        lines.push(`Cookie: ${name}`);
      });
      break;
    }
    case 'ports': {
      const ports: unknown[] = Array.isArray(r.ports) ? r.ports
        : Array.isArray(r.openPorts) ? r.openPorts : [];
      ports.slice(0, 3).forEach(p => {
        if (typeof p === 'number') { lines.push(`Port ${p}`); return; }
        if (typeof p === 'object' && p !== null) {
          const obj = p as Record<string, unknown>;
          const num = obj.port ?? obj.portNumber ?? '';
          const svc = typeof obj.service === 'string' ? obj.service : '';
          lines.push(`Port ${num}${svc ? ` (${svc})` : ''}`);
        }
      });
      break;
    }
    case 'ssl': {
      if (typeof r.issuer === 'string') lines.push(`Aussteller: ${r.issuer}`);
      if (typeof r.subject === 'string') lines.push(`Domain: ${r.subject}`);
      if (typeof r.daysUntilExpiry === 'number') lines.push(`Gültig noch: ${r.daysUntilExpiry} Tage`);
      break;
    }
    case 'tls': {
      const protos = Array.isArray(r.supportedProtocols) ? (r.supportedProtocols as string[]) : [];
      protos.slice(0, 3).forEach(p => lines.push(p));
      break;
    }
    case 'dns': {
      const recs: unknown[] = Array.isArray(r.dns) ? r.dns : [];
      recs.slice(0, 3).forEach(d => {
        if (typeof d === 'object' && d !== null) {
          const obj = d as Record<string, unknown>;
          const val = obj.address ?? obj.value ?? obj.data ?? '';
          lines.push(`${obj.type ?? '?'}: ${val}`);
        }
      });
      break;
    }
    case 'redirects': {
      const chain: unknown[] = Array.isArray(r.redirects) ? r.redirects : [];
      chain.slice(0, 3).forEach(s => {
        if (typeof s === 'string') lines.push(s);
        else if (typeof s === 'object' && s !== null && 'url' in s) lines.push((s as { url: string }).url);
      });
      break;
    }
    case 'mail-config': {
      if (!r.spf && !r.hasSPF) lines.push('SPF nicht konfiguriert');
      if (!r.dkim && !r.hasDKIM) lines.push('DKIM nicht konfiguriert');
      if (!r.dmarc && !r.hasDMARC) lines.push('DMARC nicht konfiguriert');
      break;
    }
    case 'threats': {
      if (typeof r.totalThreats === 'number' && r.totalThreats > 0)
        lines.push(`${r.totalThreats} Bedrohung${r.totalThreats !== 1 ? 'en' : ''} erkannt`);
      if (Array.isArray(r.sources)) (r.sources as string[]).slice(0, 2).forEach(s => lines.push(s));
      break;
    }
    case 'block-lists': {
      if (typeof r.listedOn === 'number' && r.listedOn > 0)
        lines.push(`Auf ${r.listedOn} Blockliste${r.listedOn !== 1 ? 'n' : ''} gelistet`);
      break;
    }
    default:
      break;
  }

  return lines;
}

// ---------------------------------------------------------------------------
// Screenshot rendering
// ---------------------------------------------------------------------------

function ScreenshotSection({ result }: { result: CheckResult }) {
  const r = result.detail as Record<string, unknown> | null;
  if (!r) return null;

  // Only data: URIs render inline — external URLs would be blocked by CSP img-src 'self' data:
  const src: string | null =
    typeof r.screenshot === 'string' ? r.screenshot
    : typeof r.image === 'string' ? r.image
    : null;

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

      {/* Check sections by group */}
      <div className="space-y-8">
        {GROUP_ORDER.map(group => {
          const items = grouped.get(group) ?? [];
          if (items.length === 0) return null;
          // Hide screenshot from main grid (rendered separately)
          const displayItems = group === 'info' ? items.filter(r => r.key !== 'screenshot') : items;
          if (displayItems.length === 0) return null;

          return (
            <section key={group}>
              <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-3">
                {GROUP_LABELS[group]}
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {displayItems.map(r => (
                  <CheckTile
                    key={r.key}
                    label={r.label}
                    status={r.status}
                    summary={r.summary}
                    detailLines={extractDetailLines(r)}
                  />
                ))}
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
