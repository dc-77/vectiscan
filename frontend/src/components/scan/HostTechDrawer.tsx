'use client';

/**
 * HostTechDrawer — Slide-Over-Sheet (Desktop rechts, Mobile Bottom-Sheet)
 * mit der vollen Tech-Tabelle fuer einen Host.
 *
 * Redesign Mai 2026: Tech-Tabelle wird aus der Host-Card herausgenommen
 * und nur on-demand geoeffnet. Default-Card zeigt nur eine kompakte
 * Tech-Summary (top-2 risikoreich) + Severity-Chips.
 *
 * Features:
 * - Filter-Pills: alle | EOL | Mega-CVE | aktuell
 * - Action-Footer: Direkter Sprung zum PerHostFindingsDrawer
 * - ESC schliesst, Tab-Cycle innerhalb
 */

import { useEffect, useMemo, useState } from 'react';

import { useDrawerA11y } from '@/hooks/useDrawerA11y';
import { TechTable } from './TechTable';
import type { TechProfile, TechRow } from '@/lib/api';

interface Props {
  techProfile: TechProfile;
  /** Anzeige-Label fuer Header (z.B. fqdn[0] oder ip). */
  hostLabel: string;
  onClose: () => void;
  /** Optional: Klick auf "Alle Befunde dieses Hosts" oeffnet Findings-Drawer. */
  onOpenFindings?: () => void;
  /** Admin-Toggle (Confidence + Source-Spalten). */
  adminView?: boolean;
}

type Filter = 'all' | 'eol' | 'mega_cve' | 'current';

const FILTER_LABEL: Record<Filter, string> = {
  all:       'alle',
  eol:       'EOL',
  mega_cve:  'Mega-CVE',
  current:   'aktuell',
};

export function HostTechDrawer({
  techProfile, hostLabel, onClose, onOpenFindings, adminView = false,
}: Props) {
  const [filter, setFilter] = useState<Filter>('all');

  // Counts pro Filter — fuer Pill-Badges
  const counts = useMemo(() => {
    const rows = (techProfile.tech_rows || []) as TechRow[];
    const eol = rows.filter((r) => r.status === 'eol' || r.status === 'minor_eol').length;
    const mega = rows.filter((r) => r.is_mega_cve).length;
    const cur = rows.filter((r) => r.status === 'current' && !r.is_mega_cve).length;
    return { all: rows.length, eol, mega_cve: mega, current: cur };
  }, [techProfile.tech_rows]);

  // Gefiltertes Profil — wir mutieren das Profil-Dict damit TechTable die
  // gefilterten Rows rendert (TechTable rendert tech_rows direkt).
  const filteredProfile = useMemo<TechProfile>(() => {
    const rows = (techProfile.tech_rows || []) as TechRow[];
    let filtered = rows;
    if (filter === 'eol') {
      filtered = rows.filter((r) => r.status === 'eol' || r.status === 'minor_eol');
    } else if (filter === 'mega_cve') {
      filtered = rows.filter((r) => r.is_mega_cve);
    } else if (filter === 'current') {
      filtered = rows.filter((r) => r.status === 'current' && !r.is_mega_cve);
    }
    return { ...techProfile, tech_rows: filtered };
  }, [techProfile, filter]);

  const drawerRef = useDrawerA11y(true);

  // ESC schliesst
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50"
      role="dialog"
      aria-modal="true"
      aria-label={`Tech-Stack fuer ${hostLabel}`}
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      {/* Slide-Over (Desktop rechts, Mobile Bottom-Sheet) */}
      <div
        ref={drawerRef}
        className="
          absolute z-10
          right-0 inset-y-0 w-full md:max-w-[680px]
          max-md:inset-x-0 max-md:top-auto max-md:bottom-0 max-md:max-h-[85vh] max-md:rounded-t-2xl
          bg-slate-950 border-l md:border-l border-slate-800 max-md:border-t
          shadow-2xl flex flex-col
        "
      >
        {/* Header */}
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-slate-800 bg-slate-950/95 px-5 py-4 backdrop-blur">
          <div>
            <div className="text-[11px] font-mono uppercase tracking-wider text-slate-500">Tech-Stack</div>
            <h2 className="mt-0.5 text-lg font-medium text-slate-100 truncate">
              <span className="font-mono text-cyan-300">{hostLabel}</span>
            </h2>
            {techProfile.fqdns && techProfile.fqdns.length > 1 && (
              <p className="mt-0.5 text-xs text-slate-400 truncate">
                {techProfile.fqdns.slice(0, 4).join(', ')}
                {techProfile.fqdns.length > 4 && ` +${techProfile.fqdns.length - 4}`}
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 text-xl leading-none px-2"
            aria-label="Schliessen"
          >
            ×
          </button>
        </div>

        {/* Filter-Pills */}
        <div className="border-b border-slate-800 bg-slate-900/40 px-5 py-2.5 flex items-center gap-1.5 flex-wrap">
          <span className="text-[11px] text-slate-500 mr-2">{counts.all} Technologien</span>
          {(Object.keys(FILTER_LABEL) as Filter[]).map((f) => {
            const c = counts[f];
            const active = filter === f;
            const disabled = f !== 'all' && c === 0;
            return (
              <button
                key={f}
                onClick={() => !disabled && setFilter(f)}
                disabled={disabled}
                className={`
                  inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px]
                  border transition-colors
                  ${active
                    ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-200'
                    : disabled
                    ? 'border-slate-800 text-slate-600 cursor-not-allowed'
                    : 'border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                  }
                `}
              >
                {FILTER_LABEL[f]}
                {f !== 'all' && (
                  <span className={active ? 'text-cyan-300' : 'text-slate-500'}>{c}</span>
                )}
              </button>
            );
          })}
        </div>

        {/* Body — Tech-Tabelle */}
        <div className="flex-1 overflow-y-auto px-5 py-4">
          {filteredProfile.tech_rows && filteredProfile.tech_rows.length > 0 ? (
            <TechTable techProfile={filteredProfile} adminView={adminView} defaultExpanded />
          ) : (
            <div className="rounded border border-slate-800 bg-slate-900/40 px-4 py-6 text-center text-sm text-slate-400">
              Keine Eintraege fuer diesen Filter.
            </div>
          )}
        </div>

        {/* Footer Action */}
        {onOpenFindings && (
          <div className="border-t border-slate-800 px-5 py-3 bg-slate-900/40">
            <button
              onClick={onOpenFindings}
              className="w-full inline-flex items-center justify-center gap-2 rounded-md bg-cyan-600 hover:bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 transition-colors"
            >
              Alle Befunde dieses Hosts anzeigen →
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
