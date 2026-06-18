'use client';

import { useState } from 'react';
import type { CheckStatus } from '@/lib/liveCheck';

// ── DS-Komponente: CheckTile (VEC-366, erweitert VEC-395) ─────────
// Check-zentriertes Tile für den SofortScan-Results-Screen.
// Pass/warn/fail über Border-Stripe + Icon + Label (nie nur Farbe).
// Progressive Disclosure: strukturierte Detail-Blöcke auf Demand.

export type BadgeVariant = 'ok' | 'warn' | 'fail' | 'neutral';

export type DetailBlock =
  | {
      type: 'kv';
      /** Optionales Abschnitts-Label über dem Block (VEC-415) */
      title?: string;
      /**
       * kind: 'code' → Tier-C-Rendering (VEC-424 Rev4): monospace im
       * horizontal scrollbaren Container ohne Umbruch — für Fingerprints,
       * Hashes, Cipher-Suites, Raw-Header, wo ein Wort-Umbruch unleserlich wäre.
       */
      items: { key: string; value: string; badge?: BadgeVariant; kind?: 'code' }[];
      /** Lange Blöcke (>8 Items) in scrollbaren Container (VEC-399) */
      scrollable?: boolean;
    }
  | {
      type: 'list';
      title?: string;
      items: { text: string; badge?: BadgeVariant }[];
      /** Lange Blöcke (>8 Items) in scrollbaren Container (VEC-399) */
      scrollable?: boolean;
    }
  | {
      type: 'badge-row';
      title?: string;
      items: { label: string; variant: BadgeVariant }[];
    };

interface CheckTileProps {
  label: string;
  status: CheckStatus;
  summary?: string;
  /** Strukturierte Detail-Blöcke (VEC-395) — ersetzt detailLines */
  detail?: DetailBlock[];
  /** Legacy-Compat: string[] → auto-konvertiert in type:'list' block */
  detailLines?: string[];
  /** Zeigt "[+N weitere im vollständigen Report]" */
  hiddenCount?: number;
  /** Übersteuert lokalen expanded-State (für "Alle aufklappen") */
  forceExpanded?: boolean;
  /** Anchor-id für Severity-Drilldown-Scroll (VEC-399): id="tile-{tileId}" */
  tileId?: string;
  /** Callback, sobald lokaler Expand-State sich ändert (für Grid-col-span in der Parent-Seite, VEC-415). */
  onExpandChange?: (expanded: boolean) => void;
  className?: string;
}

function PassIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}
function WarnIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M12 9v4" /><path d="M12 17h.01" />
      <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
    </svg>
  );
}
function FailIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="12" cy="12" r="9" /><path d="m15 9-6 6" /><path d="m9 9 6 6" />
    </svg>
  );
}
function ErrorIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="12" cy="12" r="9" /><path d="M12 8v4" /><path d="M12 16h.01" />
    </svg>
  );
}
function SpinnerIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" aria-hidden className="ds-spin">
      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
    </svg>
  );
}
function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden
      style={{ transform: open ? 'rotate(180deg)' : undefined, transition: 'transform 0.15s' }}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

const STATUS_META: Record<CheckStatus, {
  color: string; borderClass: string; Icon: React.FC; label: string;
}> = {
  pass:    { color: '#10B981', borderClass: 'border-l-2 border-emerald-500', Icon: PassIcon, label: 'OK' },
  warn:    { color: '#F59E0B', borderClass: 'border-l-2 border-amber-400',  Icon: WarnIcon, label: 'Hinweis' },
  fail:    { color: '#EF4444', borderClass: 'border-l-2 border-red-500',    Icon: FailIcon, label: 'Problem' },
  error:   { color: '#64748B', borderClass: 'border-l-2 border-slate-500',  Icon: ErrorIcon, label: 'N/A' },
  pending: { color: '#475569', borderClass: 'border-l-2 border-slate-600',  Icon: SpinnerIcon, label: 'Ausstehend' },
  running: { color: 'var(--tone-active)', borderClass: 'border-l-2 border-teal-500', Icon: SpinnerIcon, label: 'Läuft…' },
};

// ── Badge-Pill (VEC-395) — bestehende Tailwind-Tokens, keine neuen ─
const BADGE_META: Record<BadgeVariant, { text: string; bg: string; glyph: string }> = {
  ok:      { text: 'text-emerald-400', bg: 'bg-emerald-900/40', glyph: '✓' },
  warn:    { text: 'text-amber-400',   bg: 'bg-amber-900/40',   glyph: '⚠' },
  fail:    { text: 'text-red-400',     bg: 'bg-red-900/40',     glyph: '✗' },
  neutral: { text: 'text-slate-400',   bg: 'bg-slate-700/60',   glyph: '' },
};

function Pill({ variant, children }: { variant: BadgeVariant; children?: React.ReactNode }) {
  const m = BADGE_META[variant] ?? BADGE_META.neutral;
  return (
    <span className={`inline-flex shrink-0 items-center gap-1 px-1.5 py-0.5 rounded text-[11px] font-medium leading-none ${m.text} ${m.bg}`}>
      {children}
      {m.glyph && <span aria-hidden>{m.glyph}</span>}
    </span>
  );
}

// Lange Blöcke (>8 Items, scrollable) bekommen einen begrenzten Scroll-Container,
// statt Daten abzuschneiden (VEC-399, Tesler's Law: Komplexität liegt im Datensatz).
function ScrollWrap({ scrollable, children }: { scrollable?: boolean; children: React.ReactNode }) {
  if (!scrollable) return <>{children}</>;
  return <div className="max-h-48 overflow-y-auto pr-1">{children}</div>;
}

// Optionales Abschnitts-Label über einem Block (VEC-415). Reines <p> innerhalb
// der bestehenden <section> — kein semantischer Header.
function BlockTitle({ title }: { title?: string }) {
  if (!title) return null;
  return (
    <p className="text-[10px] font-semibold uppercase tracking-wide text-slate-600 mb-1">
      {title}
    </p>
  );
}

// Lange KV-Werte (>48 Zeichen: SPF, SHA-256-Fingerprint, SANs, SOA) brechen
// zeilenweise um (2-Zeilen-Layout) statt per truncate abgeschnitten zu werden
// (VEC-415 Fix B, Längenheuristik ohne DOM-Measurement).
const KV_LONG_THRESHOLD = 48;

function DetailBlockView({ block }: { block: DetailBlock }) {
  switch (block.type) {
    case 'kv':
      return (
        <div>
          <BlockTitle title={block.title} />
          <ScrollWrap scrollable={block.scrollable}>
            <div className="space-y-1.5">
              {block.items.map((it, i) =>
                // Tier C (VEC-424 Rev4): code-Werte (Fingerprint/Hash/Cipher/
                // Raw-Header) monospace im horizontal scrollbaren Container,
                // nie mitten im Wort umbrechen.
                it.kind === 'code' ? (
                  <div key={i} className="flex flex-col gap-0.5 text-xs">
                    <span className="text-slate-500 flex items-center gap-1.5">
                      {it.key}
                      {it.badge && <Pill variant={it.badge} />}
                    </span>
                    <div className="mt-0.5 overflow-x-auto rounded bg-slate-800/60 px-2 py-1">
                      <code className="font-mono text-xs text-slate-300 whitespace-nowrap">{it.value}</code>
                    </div>
                  </div>
                ) : it.value.length > KV_LONG_THRESHOLD ? (
                  // Tier B: lange Werte am Wort-Rand umbrechen (break-words),
                  // nicht mitten im Wort (vormals break-all).
                  <div key={i} className="flex flex-col gap-0.5 text-xs">
                    <span className="text-slate-500 flex items-center gap-1.5">
                      {it.key}
                      {it.badge && <Pill variant={it.badge} />}
                    </span>
                    <span className="font-mono text-slate-200 break-words leading-relaxed">{it.value}</span>
                  </div>
                ) : (
                  // Tier A: kurze Werte einzeilig, truncate.
                  <div key={i} className="flex items-center gap-3 text-xs">
                    <span className="shrink-0 text-slate-500">{it.key}</span>
                    <span className="flex-1 min-w-0 flex items-center justify-end gap-1.5">
                      <span className="min-w-0 truncate font-mono text-slate-200">{it.value}</span>
                      {it.badge && <Pill variant={it.badge} />}
                    </span>
                  </div>
                ),
              )}
            </div>
          </ScrollWrap>
        </div>
      );
    case 'list':
      return (
        <div>
          <BlockTitle title={block.title} />
          <ScrollWrap scrollable={block.scrollable}>
            <ul className="space-y-1">
              {block.items.map((it, i) => (
                <li key={i} className="flex items-start gap-2 text-xs text-slate-400">
                  {it.badge ? (
                    <span className={`mt-0.5 shrink-0 ${BADGE_META[it.badge].text}`} aria-hidden>
                      {BADGE_META[it.badge].glyph || '›'}
                    </span>
                  ) : (
                    <span className="mt-0.5 shrink-0 text-slate-600" aria-hidden>›</span>
                  )}
                  <span className="min-w-0 break-words">{it.text}</span>
                </li>
              ))}
            </ul>
          </ScrollWrap>
        </div>
      );
    case 'badge-row':
      return (
        <div>
          <BlockTitle title={block.title} />
          <div className="flex flex-wrap gap-1.5">
            {block.items.map((it, i) => (
              <Pill key={i} variant={it.variant}>{it.label}</Pill>
            ))}
          </div>
        </div>
      );
    default:
      return null;
  }
}

export default function CheckTile({
  label, status, summary, detail, detailLines = [], hiddenCount = 0,
  forceExpanded, tileId, onExpandChange, className = '',
}: CheckTileProps) {
  const [localExpanded, setLocalExpanded] = useState(false);
  const meta = STATUS_META[status] ?? STATUS_META.error;

  // Backward-Compat: detailLines → list-Block, wenn kein strukturiertes detail.
  const blocks: DetailBlock[] =
    detail && detail.length > 0
      ? detail
      : detailLines.length > 0
        ? [{ type: 'list', items: detailLines.map(t => ({ text: t })) }]
        : [];

  const hasDetail = blocks.length > 0;
  const expanded = forceExpanded !== undefined ? forceExpanded : localExpanded;
  const isLoading = status === 'pending' || status === 'running';
  const detailId = `tile-detail-${label}`;

  // Lokalen Expand-State togglen und Parent benachrichtigen (Grid-col-span, VEC-415).
  const handleToggle = () => {
    if (!hasDetail) return;
    const next = !localExpanded;
    setLocalExpanded(next);
    onExpandChange?.(next);
  };

  return (
    <div
      id={tileId ? `tile-${tileId}` : undefined}
      className={`bg-slate-800 border border-slate-700 rounded-lg ${meta.borderClass} ${className} scroll-mt-4`}
      style={{ opacity: isLoading ? 0.85 : 1 }}
    >
      <button
        type="button"
        className="w-full flex items-start gap-3 p-4 text-left"
        onClick={handleToggle}
        aria-expanded={hasDetail ? expanded : undefined}
        aria-controls={hasDetail ? detailId : undefined}
        style={{ cursor: hasDetail ? 'pointer' : 'default' }}
      >
        <span className="shrink-0 mt-0.5" style={{ color: meta.color }}>
          <meta.Icon />
        </span>
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-semibold text-slate-100 truncate">{label}</span>
          {summary && (
            <span className="block text-xs text-slate-400 mt-0.5 truncate">{summary}</span>
          )}
        </span>
        {hasDetail && (
          <span className="shrink-0 mt-1 text-slate-500">
            <ChevronIcon open={expanded} />
          </span>
        )}
      </button>

      {hasDetail && expanded && (
        <div
          id={detailId}
          className="px-4 pb-4 pt-0 border-t border-slate-700/60"
        >
          <div className="mt-3 space-y-3">
            {blocks.map((block, i) => (
              <DetailBlockView key={i} block={block} />
            ))}
          </div>
          {hiddenCount > 0 && (
            <p className="mt-3 text-xs text-teal-400/80">
              +{hiddenCount} weitere im vollständigen Report
            </p>
          )}
        </div>
      )}
    </div>
  );
}
