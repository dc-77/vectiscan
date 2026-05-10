'use client';

/**
 * TechTable — Per-Host-Tech-Tabelle in der HostMap-Card.
 *
 * Quelle: TechProfile aus /api/orders/:id/findings (Migration 027, Mai 2026).
 * Daten werden client-side aus dem TechProfile-Dict berechnet — Single Source
 * of Truth ist der Backend-Builder (report-worker/reporter/tech_table_builder.py),
 * aber fuer die UI brauchen wir keine identische Logik (Status-Klassifikation
 * basiert auf den im Profil enthaltenen cms/server/technologies-Feldern, die
 * Backend gleichermassen sieht).
 *
 * Customer-View: Technologie / Version / Kategorie / Status / EOL+Stable / CVEs
 * Admin-View: zusaetzlich Confidence + Detection-Source
 */

import { useState } from 'react';

import type { TechProfile } from '@/lib/api';

interface Props {
  techProfile: TechProfile;
  /** Wenn true: Confidence + Source-Spalten zeigen (admin/audit). */
  adminView?: boolean;
  /** Wenn true: keine Collapse-Logik — alle Rows immer sichtbar (z.B. im Drawer). */
  defaultExpanded?: boolean;
  /** Click-Handler fuer CVE-Count → springt zum Finding-Detail. */
  onCveClick?: (cves: string[]) => void;
}

interface TechRow {
  name: string;
  version: string;
  category: string;
  status: 'eol' | 'minor_eol' | 'outdated' | 'current';
  isMegaCve: boolean;
  eolDate: string;
  latestPatch: string;
  cves: string[];
  vulnName: string;
  confidence: number | null;
  source: string;
}

// Status-Style-Map (Tailwind-Klassen)
const STATUS_STYLE: Record<TechRow['status'], { label: string; cls: string }> = {
  eol:       { label: 'EOL',       cls: 'bg-red-900/60 text-red-200 border-red-700' },
  minor_eol: { label: 'Minor-EOL', cls: 'bg-yellow-900/60 text-yellow-200 border-yellow-700' },
  outdated:  { label: 'veraltet',  cls: 'bg-amber-900/60 text-amber-200 border-amber-700' },
  current:   { label: 'aktuell',   cls: 'bg-emerald-900/60 text-emerald-200 border-emerald-700' },
};

/**
 * Heuristik 1:1 zur Backend-Logik in tech_table_builder._classify_status.
 * UI rechnet nicht selbst, sondern erwartet vom Backend bereits klassifizierte
 * Daten — falls verfuegbar via `techProfile.tech_rows` (Future). Fuer jetzt
 * extrahieren wir die rohen Felder und zeigen "current" als sicheren Default.
 *
 * NOTE (Folge-PR): Backend kann ein vorberechnetes `tech_rows[]` mitliefern,
 * dann nutzt UI das direkt ohne Re-Klassifikation.
 */
function buildRowsFromProfile(profile: TechProfile): TechRow[] {
  const rows: TechRow[] = [];
  const seen = new Set<string>();

  const add = (
    name: string,
    version: string,
    category: string,
    confidence: number | null,
    source: string,
  ) => {
    const key = `${name.toLowerCase()}|${version.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    rows.push({
      name,
      version: version || '',
      category,
      status: 'current',  // Default — Backend liefert ggf. tech_rows[] mit korrektem Status
      isMegaCve: false,
      eolDate: '',
      latestPatch: '',
      cves: [],
      vulnName: '',
      confidence,
      source,
    });
  };

  if (profile.cms) {
    add(profile.cms, profile.cms_version || '', 'CMS',
        profile.cms_confidence ?? null, 'cms_fingerprint');
  }
  if (profile.server) {
    // Best-effort: "Apache/2.4.49" → name="Apache HTTP Server", version="2.4.49"
    const m = /^([A-Za-z][\w\s./-]*?)[\s/]+(\d[\d.\w-]*)\s*$/.exec(profile.server);
    if (m) {
      add(m[1].trim(), m[2].trim(), 'Web-Server', null, 'server_banner');
    } else {
      add(profile.server, '', 'Web-Server', null, 'server_banner');
    }
  }
  for (const tech of profile.technologies || []) {
    if (!tech.name) continue;
    add(tech.name, tech.version || '', 'Sonstiges', null, 'tech_detect');
  }
  if (profile.waf) {
    add(profile.waf, '', 'WAF/Schutz', null, 'waf_detect');
  }
  return rows;
}

function backendRowsToFrontend(rows: NonNullable<TechProfile['tech_rows']>): TechRow[] {
  return rows.map((r) => ({
    name: r.name,
    version: r.version,
    category: r.category,
    status: r.status,
    isMegaCve: r.is_mega_cve,
    eolDate: r.eol_date,
    latestPatch: r.latest_patch,
    cves: r.cves || [],
    vulnName: r.vuln_name,
    confidence: r.confidence,
    source: r.source,
  }));
}

export function TechTable({ techProfile, adminView = false, defaultExpanded = false, onCveClick }: Props) {
  const [expanded, setExpanded] = useState(defaultExpanded);

  // Backend liefert tech_rows[] vorberechnet (Migration 027) — Single Source of
  // Truth. Fallback: rohe Profile-Felder mit "current" als Default-Status (z.B.
  // bei alten Reports vor der Migration ohne tech_rows-Enrichment).
  const rows = techProfile.tech_rows
    ? backendRowsToFrontend(techProfile.tech_rows)
    : buildRowsFromProfile(techProfile);

  if (rows.length === 0) return null;

  const showCollapsed = !defaultExpanded && rows.length > 5 && !expanded;
  const visibleRows = showCollapsed ? rows.slice(0, 5) : rows;

  return (
    <div className="mt-2 rounded border border-slate-800 bg-slate-950/40 overflow-hidden">
      <div className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-slate-500 border-b border-slate-800">
        Eingesetzte Technologien {rows.length > 5 ? `(${rows.length})` : ''}
      </div>
      {/* Mobile: List-Pattern (md:hidden) */}
      <ul className="md:hidden divide-y divide-slate-800">
        {visibleRows.map((r, i) => {
          const sty = STATUS_STYLE[r.status];
          const extra: string[] = [];
          if (r.eolDate) extra.push(`EOL ${r.eolDate}`);
          if (r.latestPatch && r.status !== 'current') extra.push(`→ ${r.latestPatch}`);
          return (
            <li key={i} className="px-3 py-2">
              <div className="flex items-start gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-baseline gap-2">
                    <span className="text-sm text-slate-200">{r.name}</span>
                    {r.version && <span className="font-mono text-xs text-cyan-300">{r.version}</span>}
                  </div>
                  <div className="text-[10px] text-slate-500">{r.category}</div>
                  {extra.length > 0 && (
                    <div className="mt-1 text-[10px] text-slate-400">{extra.join(' · ')}</div>
                  )}
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <span className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium ${sty.cls}`}>
                    {sty.label}
                  </span>
                  {r.isMegaCve && (
                    <span className="inline-block rounded border border-orange-700 bg-orange-900/60 px-1.5 py-0.5 text-[10px] font-medium text-orange-200">
                      Mega-CVE
                    </span>
                  )}
                  {r.cves.length > 0 && (
                    onCveClick ? (
                      <button
                        onClick={() => onCveClick(r.cves)}
                        className="text-[10px] text-orange-300 hover:text-orange-200 hover:underline"
                        title={r.cves.join(', ')}
                      >
                        {r.cves.length} CVE{r.cves.length === 1 ? '' : 's'}
                      </button>
                    ) : (
                      <span className="text-[10px] text-orange-300" title={r.cves.join(', ')}>
                        {r.cves.length} CVE{r.cves.length === 1 ? '' : 's'}
                      </span>
                    )
                  )}
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      {/* Desktop: Table */}
      <table className="hidden md:table w-full text-[11px] leading-tight">
        <thead>
          <tr className="text-left text-slate-500 bg-slate-900/40">
            <th className="px-2 py-1 font-medium">Tech</th>
            <th className="px-2 py-1 font-medium">Version</th>
            <th className="px-2 py-1 font-medium">Kategorie</th>
            <th className="px-2 py-1 font-medium">Status</th>
            <th className="px-2 py-1 font-medium">EOL / Stable</th>
            <th className="px-2 py-1 font-medium">CVEs</th>
            {adminView && <th className="px-2 py-1 font-medium">Conf.</th>}
            {adminView && <th className="px-2 py-1 font-medium">Src.</th>}
          </tr>
        </thead>
        <tbody>
          {visibleRows.map((r, i) => {
            const sty = STATUS_STYLE[r.status];
            const extra: string[] = [];
            if (r.eolDate) extra.push(`EOL ${r.eolDate}`);
            if (r.latestPatch && r.status !== 'current') extra.push(`→ ${r.latestPatch}`);
            return (
              <tr key={i} className="border-t border-slate-800">
                <td className="px-2 py-1 text-slate-200">{r.name}</td>
                <td className="px-2 py-1 font-mono text-cyan-300">{r.version || '—'}</td>
                <td className="px-2 py-1 text-slate-400">{r.category}</td>
                <td className="px-2 py-1">
                  <span className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium ${sty.cls}`}>
                    {sty.label}
                  </span>
                  {r.isMegaCve && (
                    <span
                      className="ml-1 inline-block rounded border border-orange-700 bg-orange-900/60 px-1.5 py-0.5 text-[10px] font-medium text-orange-200"
                      title={r.vulnName || 'KNOWN_VULN_BUILDS-Match'}
                    >
                      Mega-CVE
                    </span>
                  )}
                </td>
                <td className="px-2 py-1 text-slate-400">{extra.join(' · ') || '—'}</td>
                <td className="px-2 py-1">
                  {r.cves.length > 0 ? (
                    onCveClick ? (
                      <button
                        onClick={() => onCveClick(r.cves)}
                        className="text-orange-300 hover:text-orange-200 hover:underline"
                        title={r.cves.join(', ')}
                      >
                        {r.cves.length}
                      </button>
                    ) : (
                      <span className="text-orange-300" title={r.cves.join(', ')}>
                        {r.cves.length}
                      </span>
                    )
                  ) : (
                    <span className="text-slate-600">—</span>
                  )}
                </td>
                {adminView && (
                  <td className="px-2 py-1 font-mono text-[10px] text-slate-400">
                    {r.confidence != null ? r.confidence.toFixed(2) : '—'}
                  </td>
                )}
                {adminView && (
                  <td className="px-2 py-1 font-mono text-[10px] text-slate-400">
                    {r.source}
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
      {!defaultExpanded && rows.length > 5 && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="block w-full px-2 py-1 text-[10px] text-slate-500 hover:text-slate-300 hover:bg-slate-900/40 border-t border-slate-800"
        >
          {expanded ? 'weniger anzeigen' : `${rows.length - 5} weitere anzeigen`}
        </button>
      )}
    </div>
  );
}
