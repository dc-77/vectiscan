'use client';

/**
 * WebsiteGallery - Per-FQDN-Section neben der IP-basierten HostMap.
 *
 * Mai 2026 (PR-F): Zeigt pro VHost/Website eine Card mit Screenshot-Thumbnail,
 * 1-Satz-Beschreibung (aus site_summary), HTTP-Status-Badge und Sprung-Link
 * zur Host-Card.
 *
 * Filter-Pillen:
 *   - "Echte Sites" (Default): site_summary.is_real_content === true
 *   - "Panels": classification === 'control_panel'
 *   - "Skipped": classification in (error/parking/non_web)
 *   - "Alle": jeder VHost mit fqdn
 */

import { useMemo, useState } from 'react';

import { ScreenshotLightbox } from './ScreenshotLightbox';
import {
  DiscoveredHost as _DiscoveredHost,
  SiteSummary,
  TechProfile,
  VHost as _VHost,
  getHostScreenshotUrl,
} from '@/lib/api';

// Re-Aliase fuer ESLint (no-unused-vars in TS-Interface)
type DiscoveredHost = _DiscoveredHost;
type VHost = _VHost;

type FilterKey = 'real' | 'panels' | 'skipped' | 'all';

interface Props {
  discoveredHosts: DiscoveredHost[] | null | undefined;
  techProfilesByIp?: Record<string, TechProfile> | undefined;
  orderId: string;
}

interface WebsiteEntry {
  fqdn: string;
  status: number | null;
  title: string | null;
  screenshotKey: string | null;
  summary: SiteSummary | null;
  parentIp: string;
  isPrimary: boolean;
  isSkipped: boolean;
  techProfile?: TechProfile;
}

const FILTER_LABEL: Record<FilterKey, string> = {
  real: 'Echte Sites',
  panels: 'Panels',
  skipped: 'Skipped',
  all: 'Alle',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function flattenVhosts(
  hosts: DiscoveredHost[] | null | undefined,
  techProfilesByIp: Record<string, TechProfile> | undefined,
): WebsiteEntry[] {
  if (!hosts) return [];
  const out: WebsiteEntry[] = [];
  for (const h of hosts) {
    const tp = techProfilesByIp?.[h.ip];
    for (const v of (h.vhosts as VHost[] | undefined) ?? []) {
      out.push({
        fqdn: v.fqdn,
        status: v.status ?? null,
        title: v.title ?? null,
        screenshotKey: v.screenshot_minio_key ?? null,
        summary: v.site_summary ?? null,
        parentIp: h.ip,
        isPrimary: v.is_primary ?? false,
        isSkipped: false,
        techProfile: tp,
      });
    }
    for (const sk of h.vhost_skipped ?? []) {
      out.push({
        fqdn: sk.fqdn,
        status: sk.status ?? null,
        title: sk.title ?? null,
        screenshotKey: null,
        // site_summary kann auch auf vhost_skipped-Entries liegen (vom Worker
        // gesetzt). Wir lesen optional zur Sicherheit, fallback: synthetic.
        summary: ((sk as unknown) as { site_summary?: SiteSummary | null }).site_summary
          ?? null,
        parentIp: h.ip,
        isPrimary: false,
        isSkipped: true,
        techProfile: tp,
      });
    }
  }
  return out;
}

function matchFilter(e: WebsiteEntry, f: FilterKey): boolean {
  const cls = e.summary?.classification;
  if (f === 'all') return true;
  if (f === 'real') {
    if (e.summary?.is_real_content === true) return true;
    // Wenn kein site_summary vorhanden ist (Order vor PR-E): fall back auf
    // Status 2xx/3xx und nicht-skipped.
    if (!e.summary && !e.isSkipped && e.status != null && e.status < 400) return true;
    return false;
  }
  if (f === 'panels') return cls === 'control_panel';
  if (f === 'skipped') {
    if (cls === 'error' || cls === 'parking' || cls === 'non_web') return true;
    if (e.isSkipped && !cls) return true; // Order vor PR-E
    return false;
  }
  return false;
}

function statusBadgeClass(status: number | null): string {
  if (status == null) return 'bg-slate-800 text-slate-400 border-slate-700';
  if (status >= 200 && status < 300) return 'bg-emerald-900/40 text-emerald-300 border-emerald-700/60';
  if (status >= 300 && status < 400) return 'bg-cyan-900/40 text-cyan-300 border-cyan-700/60';
  if (status >= 400 && status < 500) return 'bg-amber-900/40 text-amber-200 border-amber-700/60';
  return 'bg-red-900/40 text-red-200 border-red-700/60';
}

function classificationLabel(cls: SiteSummary['classification'] | undefined): string {
  switch (cls) {
    case 'web_content': return 'Webseite';
    case 'control_panel': return 'Verwaltungspanel';
    case 'login_only': return 'Login';
    case 'parking': return 'Parking';
    case 'error': return 'Fehlerseite';
    case 'non_web': return 'Kein Web';
    default: return '';
  }
}

function pickTechChips(tp: TechProfile | undefined, max = 2): string[] {
  if (!tp?.tech_rows) return [];
  return tp.tech_rows
    .slice() // copy
    .sort((a, b) => {
      // EOL / Mega-CVE zuerst, dann nach Name
      const aBad = a.status === 'eol' || a.is_mega_cve ? 0 : 1;
      const bBad = b.status === 'eol' || b.is_mega_cve ? 0 : 1;
      if (aBad !== bBad) return aBad - bBad;
      return a.name.localeCompare(b.name);
    })
    .slice(0, max)
    .map((r) => (r.version ? `${r.name} ${r.version}` : r.name));
}

function scrollToHost(ip: string): void {
  const el = document.getElementById(`host-${ip}`);
  if (!el) return;
  const y = el.getBoundingClientRect().top + window.scrollY - 100;
  window.scrollTo({ top: y, behavior: 'smooth' });
  // Visual highlight (Flash)
  el.classList.add('ring-2', 'ring-cyan-400', 'transition-shadow');
  window.setTimeout(() => {
    el.classList.remove('ring-2', 'ring-cyan-400');
  }, 1800);
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function WebsiteGallery({ discoveredHosts, techProfilesByIp, orderId }: Props) {
  const [filter, setFilter] = useState<FilterKey>('real');
  const [lightbox, setLightbox] = useState<{ url: string; label: string } | null>(null);

  const entries = useMemo(
    () => flattenVhosts(discoveredHosts, techProfilesByIp),
    [discoveredHosts, techProfilesByIp],
  );

  const counts: Record<FilterKey, number> = useMemo(() => ({
    real: entries.filter((e) => matchFilter(e, 'real')).length,
    panels: entries.filter((e) => matchFilter(e, 'panels')).length,
    skipped: entries.filter((e) => matchFilter(e, 'skipped')).length,
    all: entries.length,
  }), [entries]);

  const visible = useMemo(
    () => entries.filter((e) => matchFilter(e, filter)),
    [entries, filter],
  );

  if (entries.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6 text-center">
        <div className="text-3xl mb-2 opacity-60" aria-hidden>🌐</div>
        <div className="text-sm text-slate-400 font-medium">Keine Webseiten erkannt</div>
        <div className="mt-1 text-xs text-slate-500">
          In diesem Scan wurden keine FQDN-basierten Webseiten gefunden. Reines
          IP-Scan oder Pre-Check noch nicht abgeschlossen.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Filter-Pillen */}
      <div className="flex flex-wrap items-center gap-1.5 overflow-x-auto pb-1">
        {(Object.keys(FILTER_LABEL) as FilterKey[]).map((f) => {
          const active = filter === f;
          return (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`
                inline-flex items-center gap-1.5 whitespace-nowrap rounded-md
                border px-2.5 py-1 text-xs transition-colors
                ${active
                  ? 'bg-cyan-500/20 text-cyan-200 border-cyan-700'
                  : 'bg-slate-900/40 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-600'
                }
              `}
              aria-pressed={active}
            >
              {FILTER_LABEL[f]}
              <span className={`tabular-nums ${active ? 'text-cyan-300' : 'text-slate-500'}`}>
                {counts[f]}
              </span>
            </button>
          );
        })}
      </div>

      {/* Gallery-Grid */}
      {visible.length === 0 ? (
        <div className="rounded-lg border border-slate-800 bg-slate-900/30 p-4 text-center text-xs text-slate-500">
          Keine Eintraege fuer den gewaehlten Filter — klicke auf <span className="font-medium text-slate-300">Alle</span>.
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {visible.map((e) => (
            <WebsiteCard
              key={`${e.parentIp}-${e.fqdn}`}
              entry={e}
              orderId={orderId}
              onOpenLightbox={(url, label) => setLightbox({ url, label })}
              onJumpToHost={() => scrollToHost(e.parentIp)}
            />
          ))}
        </div>
      )}

      {lightbox && (
        <ScreenshotLightbox
          url={lightbox.url}
          hostLabel={lightbox.label}
          onClose={() => setLightbox(null)}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Website-Card
// ---------------------------------------------------------------------------

interface CardProps {
  entry: WebsiteEntry;
  orderId: string;
  onOpenLightbox: (url: string, label: string) => void;
  onJumpToHost: () => void;
}

function WebsiteCard({ entry, orderId, onOpenLightbox, onJumpToHost }: CardProps) {
  const url = entry.screenshotKey ? getHostScreenshotUrl(orderId, entry.screenshotKey) : null;
  const chips = pickTechChips(entry.techProfile);
  const description = entry.summary?.description;
  const cls = entry.summary?.classification;
  const isSkipped = entry.isSkipped || cls === 'error' || cls === 'parking' || cls === 'non_web';

  return (
    <div
      className={`
        flex flex-col gap-2 rounded-lg border bg-slate-900/60
        ${isSkipped ? 'border-slate-800 opacity-80' : 'border-slate-700'}
        hover:border-slate-600 transition-colors
      `}
    >
      {/* Thumbnail */}
      {url ? (
        <button
          onClick={() => onOpenLightbox(url, entry.fqdn)}
          className="block aspect-[16/9] overflow-hidden rounded-t-lg bg-slate-950 border-b border-slate-800 group"
          aria-label={`Screenshot ${entry.fqdn} oeffnen`}
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={url}
            alt={`Screenshot ${entry.fqdn}`}
            className="h-full w-full object-cover object-top group-hover:opacity-90 transition-opacity"
            loading="lazy"
          />
        </button>
      ) : (
        <div className="aspect-[16/9] flex items-center justify-center rounded-t-lg bg-slate-950 border-b border-slate-800 text-slate-700">
          <div className="text-center">
            <div className="text-3xl opacity-50" aria-hidden>
              {cls === 'non_web' ? '⚙' : cls === 'parking' ? '🅿' : '∅'}
            </div>
            <div className="mt-1 text-[10px] uppercase tracking-wider text-slate-600">
              kein Screenshot
            </div>
          </div>
        </div>
      )}

      {/* Body */}
      <div className="px-3 pb-3 space-y-2">
        {/* FQDN + Status */}
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono text-xs text-cyan-300 truncate flex-1" title={entry.fqdn}>
            {entry.fqdn}
          </span>
          <span
            className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] ${statusBadgeClass(entry.status)}`}
            title={entry.status != null ? `HTTP-Status ${entry.status}` : 'Kein HTTP-Status'}
          >
            {entry.status ?? '—'}
          </span>
          {entry.isPrimary && (
            <span
              className="shrink-0 rounded border border-emerald-700/40 bg-emerald-900/30 px-1 py-0.5 text-[9px] font-mono text-emerald-300"
              title="Primary VHost"
            >
              P
            </span>
          )}
        </div>

        {/* Classification-Tag */}
        {cls && (
          <div className="text-[10px] uppercase tracking-wider text-slate-500">
            {classificationLabel(cls)}
          </div>
        )}

        {/* Description (line-clamp-2) */}
        {description && (
          <div className="text-xs text-slate-300 line-clamp-2 leading-snug">
            {description}
          </div>
        )}

        {/* Tech-Chips */}
        {chips.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-0.5">
            {chips.map((c) => (
              <span
                key={c}
                className="inline-block rounded border border-slate-700 bg-slate-800/40 px-1.5 py-0.5 text-[10px] text-slate-300"
              >
                {c}
              </span>
            ))}
          </div>
        )}

        {/* Footer-Link */}
        <div className="flex items-center justify-between pt-1 border-t border-slate-800/60">
          <button
            onClick={onJumpToHost}
            className="text-[11px] text-cyan-400 hover:text-cyan-300 hover:underline truncate"
            title={`Auf Host ${entry.parentIp} springen`}
          >
            → Host {entry.parentIp}
          </button>
          {entry.title && (
            <span className="text-[10px] text-slate-500 truncate max-w-[50%]" title={entry.title}>
              {entry.title}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

export default WebsiteGallery;
