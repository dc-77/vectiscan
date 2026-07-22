'use client';

/**
 * HostMap — Grid mit einer Karte pro Host. Zeigt KI-Targeting-Decision
 * (Priority-Badge P1/P2/P3 + scan/skip-Status) und das Reasoning auf
 * einen Klick / Hover.
 *
 * Datenquellen:
 *   - aiStrategy.hosts[]: { ip, action, priority, reasoning, scan_hints }
 *     (aus /api/orders/:id/events)
 *   - discoveredHosts: Fallback wenn keine AI-Strategy vorliegt
 *   - techProfilesByIp: Phase-1-Tech-Profile pro IP (Migration 027, Mai 2026,
 *     aus /api/orders/:id/findings.tech_profiles[]) — speist die TechTable
 *     pro Host-Card.
 */

import { useState } from 'react';

import { HostTechDrawer } from './HostTechDrawer';
import { PerHostFindingsDrawer } from './PerHostFindingsDrawer';
import { ScreenshotLightbox } from './ScreenshotLightbox';
import type { TechProfile, TechRow } from '@/lib/api';

interface AiHost {
  ip: string;
  action?: 'scan' | 'skip';
  priority?: number | null;
  reasoning?: string;
  scan_hints?: Record<string, unknown>;
}

interface VHostAlias {
  fqdn: string;
  status?: number | null;
  reason?: string;
}

interface VHost {
  fqdn: string;
  status?: number | null;
  title?: string | null;
  final_url?: string | null;
  is_primary?: boolean;
  aliases?: VHostAlias[];
}

interface DiscoveredHost {
  ip: string;
  fqdns?: string[];
  hostname?: string;
  screenshot_minio_key?: string | null;
  // Multi-VHost-Probe (Mai 2026)
  vhosts?: VHost[];
  vhost_skipped?: Array<{ fqdn: string; reason?: string; status?: number | null }>;
}

interface Props {
  aiHosts: AiHost[] | null | undefined;
  discoveredHosts: DiscoveredHost[] | null | undefined;
  strategyNotes?: string | null;
  /** Migration 027: Phase-1-Tech-Profile pro IP. Speist die TechTable pro Host. */
  techProfilesByIp?: Record<string, TechProfile> | undefined;
  // PR-Screenshots: optional, fuer Thumbnail-Anzeige bei Hosts mit Web-Content.
  orderId?: string;
}

import { getHostScreenshotUrl } from '@/lib/api';

const PRIORITY_STYLES: Record<string, { badge: string; label: string }> = {
  '1': { badge: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30',     label: 'P1' },
  '2': { badge: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30', label: 'P2' },
  '3': { badge: 'bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30',   label: 'P3' },
};

function fqdnFor(host: AiHost | DiscoveredHost, discoveredHosts: DiscoveredHost[] | null | undefined): string {
  // AiHost-Branch: keine fqdns; lookup via discoveredHosts.
  const dh = discoveredHosts?.find((d) => d.ip === host.ip);
  return dh?.fqdns?.[0] ?? dh?.hostname ?? '';
}

function screenshotKeyFor(
  host: AiHost | DiscoveredHost,
  discoveredHosts: DiscoveredHost[] | null | undefined,
): string | null {
  const dh = discoveredHosts?.find((d) => d.ip === host.ip);
  return dh?.screenshot_minio_key ?? null;
}

// Severity-Rang fuer Tech-Summary-Sortierung — eol > minor_eol > outdated > current,
// is_mega_cve gewinnt bei gleichem Status.
const STATUS_RANK: Record<TechRow['status'], number> = {
  eol: 0, minor_eol: 1, outdated: 2, current: 3, unbekannt: 4,
};

function pickTopTechs(rows: TechRow[] | undefined, limit = 2): TechRow[] {
  if (!rows || rows.length === 0) return [];
  const sorted = [...rows].sort((a, b) => {
    const sa = STATUS_RANK[a.status] ?? 99;
    const sb = STATUS_RANK[b.status] ?? 99;
    if (sa !== sb) return sa - sb;
    if ((a.is_mega_cve ? 0 : 1) !== (b.is_mega_cve ? 0 : 1)) {
      return (a.is_mega_cve ? 0 : 1) - (b.is_mega_cve ? 0 : 1);
    }
    return a.name.localeCompare(b.name);
  });
  return sorted.slice(0, limit);
}

function abnormalChips(rows: TechRow[] | undefined): Array<'eol' | 'minor_eol' | 'outdated' | 'mega_cve'> {
  if (!rows || rows.length === 0) return [];
  const set = new Set<'eol' | 'minor_eol' | 'outdated' | 'mega_cve'>();
  for (const r of rows) {
    if (r.status === 'eol') set.add('eol');
    else if (r.status === 'minor_eol') set.add('minor_eol');
    else if (r.status === 'outdated') set.add('outdated');
    if (r.is_mega_cve) set.add('mega_cve');
  }
  return Array.from(set);
}

const CHIP_STYLE: Record<string, { label: string; cls: string }> = {
  eol:       { label: 'EOL',       cls: 'bg-red-900/60 text-red-200 border-red-700' },
  minor_eol: { label: 'Minor-EOL', cls: 'bg-yellow-900/60 text-yellow-200 border-yellow-700' },
  outdated:  { label: 'veraltet',  cls: 'bg-amber-900/60 text-amber-200 border-amber-700' },
  mega_cve:  { label: 'Mega-CVE',  cls: 'bg-orange-900/60 text-orange-200 border-orange-700' },
};

export default function HostMap({ aiHosts, discoveredHosts, strategyNotes, orderId, techProfilesByIp }: Props) {
  const [findingsDrawerHost, setFindingsDrawerHost] = useState<string | null>(null);
  const [techDrawerIp, setTechDrawerIp] = useState<string | null>(null);
  const [lightbox, setLightbox] = useState<{ url: string; label: string } | null>(null);
  // Wenn keine aiStrategy vorliegt: simple Liste der discovered hosts
  if (!aiHosts || aiHosts.length === 0) {
    if (!discoveredHosts || discoveredHosts.length === 0) {
      return (
        <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-6 text-center">
          <div className="text-3xl mb-2 opacity-60" aria-hidden>🔍</div>
          <div className="text-sm text-slate-400 font-medium">Noch keine Host-Daten</div>
          <div className="mt-1 text-xs text-slate-500">
            Pre-Check läuft. Sobald Targets validiert und DNS aufgelöst sind, erscheinen die Hosts hier.
          </div>
        </div>
      );
    }
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
        <div className="mb-2 text-sm text-slate-400">
          {discoveredHosts.length} Host{discoveredHosts.length === 1 ? '' : 's'} gefunden — KI-Strategie noch nicht angewendet
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {discoveredHosts.map((h) => (
            <div key={h.ip} className="rounded border border-slate-800 bg-slate-950/40 px-3 py-2 text-sm">
              <div className="font-mono text-cyan-300">{h.ip}</div>
              {h.fqdns?.[0] && <div className="text-slate-400 text-xs truncate">{h.fqdns[0]}</div>}
            </div>
          ))}
        </div>
      </div>
    );
  }

  const scanned = aiHosts.filter((h) => h.action !== 'skip');
  const skipped = aiHosts.filter((h) => h.action === 'skip');

  return (
    <div className="space-y-4">
      {strategyNotes && (
        <div className="rounded-lg border border-cyan-900/40 bg-cyan-950/20 p-3 text-xs leading-relaxed text-cyan-100/80">
          <span className="mb-1 inline-block font-mono text-[10px] uppercase tracking-wider text-cyan-400">
            ▸ Strategie
          </span>
          <div>{strategyNotes}</div>
        </div>
      )}

      <div>
        <div className="mb-2 flex items-baseline justify-between">
          <h3 className="text-sm font-medium text-slate-300">Hosts ({aiHosts.length})</h3>
          <div className="text-xs text-slate-500 tabular-nums">
            {scanned.length} scan · {skipped.length} skip
          </div>
        </div>

        {/* Scanned-Hosts-Grid */}
        {scanned.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {scanned.map((h) => (
              <ScannedHostCard
                key={h.ip}
                host={h}
                discoveredHosts={discoveredHosts}
                techProfile={techProfilesByIp?.[h.ip]}
                orderId={orderId}
                onOpenFindings={(label) => setFindingsDrawerHost(label)}
                onOpenTech={(ip) => setTechDrawerIp(ip)}
                onOpenLightbox={(url, label) => setLightbox({ url, label })}
              />
            ))}
          </div>
        )}

        {/* Skipped-Hosts in Disclosure (default zu) */}
        {skipped.length > 0 && (
          <details className="mt-3 rounded-lg border border-slate-800 bg-slate-950/30">
            <summary className="cursor-pointer px-3 py-2 text-xs text-slate-400 hover:text-slate-200 select-none">
              <span className="mr-1">▸</span>
              {skipped.length} Skipped Host{skipped.length === 1 ? '' : 's'} anzeigen
            </summary>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 px-3 pb-3">
              {skipped.map((h) => (
                <SkippedHostCard key={h.ip} host={h} discoveredHosts={discoveredHosts} />
              ))}
            </div>
          </details>
        )}
      </div>

      {/* Drawers + Lightbox */}
      {findingsDrawerHost && orderId && (
        <PerHostFindingsDrawer
          orderId={orderId}
          host={findingsDrawerHost}
          onClose={() => setFindingsDrawerHost(null)}
        />
      )}
      {techDrawerIp && techProfilesByIp?.[techDrawerIp] && (
        <HostTechDrawer
          techProfile={techProfilesByIp[techDrawerIp]}
          hostLabel={techProfilesByIp[techDrawerIp].fqdns?.[0] || techDrawerIp}
          onClose={() => setTechDrawerIp(null)}
          onOpenFindings={() => {
            const label = techProfilesByIp[techDrawerIp].fqdns?.[0] || techDrawerIp;
            setTechDrawerIp(null);
            setFindingsDrawerHost(label);
          }}
        />
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

// ─── Card-Components ──────────────────────────────────────────────────────

interface ScannedHostCardProps {
  host: AiHost;
  discoveredHosts: DiscoveredHost[] | null | undefined;
  techProfile?: TechProfile;
  orderId?: string;
  onOpenFindings: (label: string) => void;
  onOpenTech: (ip: string) => void;
  onOpenLightbox: (url: string, label: string) => void;
}

function ScannedHostCard({
  host, discoveredHosts, techProfile, orderId,
  onOpenFindings, onOpenTech, onOpenLightbox,
}: ScannedHostCardProps) {
  const fqdn = fqdnFor(host, discoveredHosts);
  const prio = host.priority ? PRIORITY_STYLES[String(host.priority)] : null;
  const dh = discoveredHosts?.find((d) => d.ip === host.ip);
  const vhosts = dh?.vhosts || [];
  const screenshotKey = screenshotKeyFor(host, discoveredHosts);
  const screenshotUrl = orderId && screenshotKey
    ? getHostScreenshotUrl(orderId, screenshotKey)
    : null;
  const techRows = techProfile?.tech_rows || [];
  const topTechs = pickTopTechs(techRows);
  const chips = abnormalChips(techRows);
  const techLabel = techProfile?.fqdns?.[0] || host.ip;

  // PR-F (Mai 2026): Anchor-ID fuer Cross-Linking aus der Websites-Section.
  // `vhosts` enthaelt alle primary VHosts dieses Hosts; der Chip rechts oben
  // springt zur Websites-Section + scrollt sie ggf. in den Viewport.
  const websiteCount = vhosts.length + (
    (discoveredHosts?.find((d) => d.ip === host.ip)?.vhost_skipped?.length) || 0
  );
  const handleJumpToWebsites = () => {
    const el = document.getElementById('websites');
    if (!el) return;
    const y = el.getBoundingClientRect().top + window.scrollY - 100;
    window.scrollTo({ top: y, behavior: 'smooth' });
  };

  return (
    <div
      id={`host-${host.ip}`}
      className="
      flex flex-col gap-2 rounded-lg border border-slate-700 bg-slate-900/60 p-3
      hover:border-slate-600 transition-colors
    "
    >
      {/* Header: Priority + Status + IP + Websites-Chip */}
      <div className="flex items-center gap-2">
        {prio && (
          <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${prio.badge}`}>
            {prio.label}
          </span>
        )}
        <span
          className="text-base text-emerald-400"
          aria-label="scanned"
          title="Scanned"
        >
          ✓
        </span>
        <span className="font-mono text-xs text-cyan-300 truncate flex-1">{host.ip}</span>
        {websiteCount > 0 && (
          <button
            onClick={handleJumpToWebsites}
            className="shrink-0 rounded border border-slate-700 bg-slate-800/40 px-1.5 py-0.5 text-[10px] text-slate-300 hover:bg-slate-700 hover:text-cyan-200 transition-colors"
            title="Zur Websites-Section springen"
          >
            {websiteCount} Website{websiteCount === 1 ? '' : 's'} ↑
          </button>
        )}
      </div>

      {/* Primaer-FQDN */}
      {fqdn && (
        <div className="text-xs text-slate-300 truncate">{fqdn}</div>
      )}

      {/* VHost-Summary (kompakt: nur wenn >1 VHost) */}
      {vhosts.length > 1 && (
        <div className="text-[11px] text-slate-500 truncate">
          +{vhosts.length - 1} VHost{vhosts.length - 1 === 1 ? '' : 's'}
          {vhosts[0]?.status && (
            <span className={`ml-2 ${vhosts[0].status >= 200 && vhosts[0].status < 300
              ? 'text-emerald-400/80' : 'text-amber-400/80'}`}>
              · {vhosts[0].status}
            </span>
          )}
        </div>
      )}

      {/* Tech-Summary + Severity-Chips (nur wenn techProfile vorhanden) */}
      {(topTechs.length > 0 || chips.length > 0) && (
        <div className="flex flex-col gap-1.5 border-t border-slate-800 pt-2">
          {topTechs.length > 0 && (
            <div className="text-[11px] text-slate-300 truncate">
              {topTechs.map((t, i) => (
                <span key={i}>
                  {i > 0 && <span className="text-slate-600 mx-1.5">·</span>}
                  <span className="text-slate-200">{t.name}</span>
                  {t.version && <span className="text-cyan-300/80 ml-1">{t.version}</span>}
                </span>
              ))}
            </div>
          )}
          {chips.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {chips.slice(0, 3).map((c) => {
                const sty = CHIP_STYLE[c];
                return (
                  <span
                    key={c}
                    className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium ${sty.cls}`}
                  >
                    {sty.label}
                  </span>
                );
              })}
              {techRows.length > 0 && (
                <button
                  onClick={() => onOpenTech(host.ip)}
                  className="ml-auto text-[10px] text-slate-500 hover:text-slate-300 hover:underline"
                >
                  {techRows.length} Tech ▸
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* AI-Reasoning, line-clamp-3 */}
      {host.reasoning ? (
        <div className="text-xs leading-snug text-slate-400 line-clamp-3 min-h-[3em] flex-1">
          {host.reasoning}
        </div>
      ) : (
        <div className="text-xs leading-snug text-slate-600 italic min-h-[3em] flex-1">
          — Kein Targeting-Reasoning
        </div>
      )}

      {/* Action-Row: 3 Buttons */}
      <div className="flex gap-1.5 pt-2 border-t border-slate-800">
        {orderId && (
          <button
            onClick={() => onOpenFindings(fqdn || host.ip)}
            className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-md bg-slate-800/80 hover:bg-slate-700 px-2 py-1.5 text-[11px] text-slate-300 transition-colors"
            title="Alle Befunde dieses Hosts"
          >
            <span aria-hidden>≡</span> Befunde
          </button>
        )}
        <button
          onClick={() => techRows.length > 0 && onOpenTech(host.ip)}
          disabled={techRows.length === 0}
          className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-md bg-slate-800/80 hover:bg-slate-700 disabled:bg-slate-900/40 disabled:text-slate-600 disabled:cursor-not-allowed px-2 py-1.5 text-[11px] text-slate-300 transition-colors"
          title={techRows.length > 0 ? `${techRows.length} Technologien` : 'Kein Tech-Profile'}
        >
          <span aria-hidden>⌘</span> Tech-Stack {techRows.length > 0 && <span className="text-slate-500">({techRows.length})</span>}
        </button>
        <button
          onClick={() => screenshotUrl && onOpenLightbox(screenshotUrl, techLabel)}
          disabled={!screenshotUrl}
          className="flex-1 inline-flex items-center justify-center gap-1.5 rounded-md bg-slate-800/80 hover:bg-slate-700 disabled:bg-slate-900/40 disabled:text-slate-600 disabled:cursor-not-allowed px-2 py-1.5 text-[11px] text-slate-300 transition-colors"
          title={screenshotUrl ? 'Site-Screenshot anzeigen' : 'Kein Screenshot verfuegbar'}
        >
          <span aria-hidden>🖼</span> Site
        </button>
      </div>
    </div>
  );
}

interface SkippedHostCardProps {
  host: AiHost;
  discoveredHosts: DiscoveredHost[] | null | undefined;
}

function SkippedHostCard({ host, discoveredHosts }: SkippedHostCardProps) {
  const fqdn = fqdnFor(host, discoveredHosts);
  const prio = host.priority ? PRIORITY_STYLES[String(host.priority)] : null;
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/40 p-2.5">
      <div className="flex items-center gap-2">
        {prio && (
          <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${prio.badge}`}>
            {prio.label}
          </span>
        )}
        <span className="text-base text-slate-500" aria-label="skipped" title="Skipped">⊘</span>
        <span className="font-mono text-xs text-slate-400 truncate flex-1">{host.ip}</span>
      </div>
      {fqdn && <div className="mt-1 text-xs truncate text-slate-500">{fqdn}</div>}
      {host.reasoning && (
        <div className="mt-1.5 text-[11px] leading-snug text-slate-500 line-clamp-2">
          {host.reasoning}
        </div>
      )}
    </div>
  );
}
