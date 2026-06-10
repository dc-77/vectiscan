'use client';

import { useState } from 'react';
import type { CheckStatus } from '@/lib/liveCheck';

// ── DS-Komponente: CheckTile (VEC-366) ───────────────────────────
// Check-zentriertes Tile für den SofortScan-Results-Screen.
// Pass/warn/fail über Border-Stripe + Icon + Label (nie nur Farbe).
// Progressive Disclosure: Detail auf Demand aufklappbar.

interface CheckTileProps {
  label: string;
  status: CheckStatus;
  summary?: string;
  /** Max. 3 Detail-Zeilen sichtbar, Rest gated */
  detailLines?: string[];
  /** Zeigt "[+N weitere im vollständigen Report]" */
  hiddenCount?: number;
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

export default function CheckTile({
  label, status, summary, detailLines = [], hiddenCount = 0, className = '',
}: CheckTileProps) {
  const [expanded, setExpanded] = useState(false);
  const meta = STATUS_META[status] ?? STATUS_META.error;
  const hasDetail = detailLines.length > 0;
  const isLoading = status === 'pending' || status === 'running';

  return (
    <div
      className={`bg-slate-800 border border-slate-700 rounded-lg ${meta.borderClass} ${className}`}
      style={{ opacity: isLoading ? 0.85 : 1 }}
    >
      <button
        type="button"
        className="w-full flex items-start gap-3 p-4 text-left"
        onClick={() => hasDetail && setExpanded(v => !v)}
        aria-expanded={hasDetail ? expanded : undefined}
        aria-controls={hasDetail ? `tile-detail-${label}` : undefined}
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
          id={`tile-detail-${label}`}
          className="px-4 pb-4 pt-0 border-t border-slate-700/60"
        >
          <ul className="mt-3 space-y-1">
            {detailLines.map((line, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-slate-400">
                <span className="mt-0.5 shrink-0 text-slate-600">›</span>
                <span>{line}</span>
              </li>
            ))}
          </ul>
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
