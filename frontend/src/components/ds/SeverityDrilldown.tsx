'use client';

import { useState } from 'react';
import type { CheckResult } from '@/lib/liveCheck';

// ── DS-Komponente: SeverityDrilldown (VEC-399) ───────────────────
// Schlüsselt die aggregierten Hero-Severity-Zahlen (z.B. "2H · 4M · 13I")
// in konkrete Befunde auf. Zwei Sektionen: kritische Befunde (fail → H,
// immer offen) + Hinweise (warn → M, collapsible). Klick auf eine Zeile
// → Anchor-Scroll zur zugehörigen CheckTile + Auto-Expand (via onSelect).
// Mapping fail→H / warn→M / pass→I (siehe buildSeverityCounts) — pass
// (Info) wird hier bewusst NICHT gelistet, das sind die "alles ok"-Module.

interface SeverityDrilldownProps {
  results: CheckResult[];
  onSelect: (key: string) => void;
  className?: string;
}

function FailIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="12" cy="12" r="9" /><path d="m15 9-6 6" /><path d="m9 9 6 6" />
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
function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden
      style={{ transform: open ? 'rotate(180deg)' : undefined, transition: 'transform 0.15s' }}>
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

function DrilldownRow({
  item, color, Icon, onSelect,
}: {
  item: CheckResult;
  color: string;
  Icon: React.FC;
  onSelect: (key: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onSelect(item.key)}
      className="w-full flex items-center gap-3 px-2 py-2 rounded-lg hover:bg-slate-700/50 transition-colors text-left min-h-[44px]"
    >
      <span style={{ color }} className="shrink-0"><Icon /></span>
      <span className="text-sm font-medium text-slate-100 shrink-0">{item.label}</span>
      {item.summary && (
        <span className="text-xs text-slate-400 flex-1 min-w-0 truncate">{item.summary}</span>
      )}
      <span className="text-slate-500 shrink-0 text-sm ml-auto pl-2" aria-hidden>›</span>
    </button>
  );
}

export default function SeverityDrilldown({ results, onSelect, className = '' }: SeverityDrilldownProps) {
  const [warnOpen, setWarnOpen] = useState(false);

  const failItems = results.filter(r => r.status === 'fail');
  const warnItems = results.filter(r => r.status === 'warn');

  if (failItems.length === 0 && warnItems.length === 0) return null;

  return (
    <div className={`mb-8 rounded-xl border border-slate-700 bg-slate-800/50 px-4 py-3 ${className}`}>
      {/* A) Kritische Befunde (fail → H) — immer aufgeklappt */}
      {failItems.length > 0 && (
        <div>
          <h3 className="text-[11px] font-semibold uppercase tracking-wide text-red-400 px-2 mb-1">
            Kritische Befunde ({failItems.length})
          </h3>
          <div className="space-y-0.5">
            {failItems.map(item => (
              <DrilldownRow key={item.key} item={item} color="#EF4444" Icon={FailIcon} onSelect={onSelect} />
            ))}
          </div>
        </div>
      )}

      {/* B) Hinweise (warn → M) — collapsible, default zu */}
      {warnItems.length > 0 && (
        <div className={failItems.length > 0 ? 'mt-2 pt-2 border-t border-slate-700/60' : ''}>
          <button
            type="button"
            onClick={() => setWarnOpen(v => !v)}
            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-slate-700/40 transition-colors"
            aria-expanded={warnOpen}
          >
            <h3 className="text-[11px] font-semibold uppercase tracking-wide text-amber-400">
              Hinweise ({warnItems.length})
            </h3>
            <span className="text-slate-500 ml-auto flex items-center gap-1 text-xs">
              {warnOpen ? 'einklappen' : 'öffnen'}
              <ChevronIcon open={warnOpen} />
            </span>
          </button>
          {warnOpen && (
            <div className="space-y-0.5 mt-1">
              {warnItems.map(item => (
                <DrilldownRow key={item.key} item={item} color="#F59E0B" Icon={WarnIcon} onSelect={onSelect} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
