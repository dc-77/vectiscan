'use client';

/**
 * ToolTrace — admin-only Debug-Tab mit allen Tool-Aufrufen + Outputs.
 *
 * Zeigt jede Zeile in `scan_results` (ausser AI-Debug-Eintraege und
 * Meta-Entries wie report_cost / phase3_correlation) als expand-bare
 * Karte: Tool, Host, Phase, Exit-Code, Dauer, Timestamp + raw_output
 * (truncated 1000 Zeichen, mit "Vollstaendig anzeigen"-Toggle).
 *
 * Wenn fuer den Host eine Phase-2-Config (aiConfigs[host]) vorliegt,
 * werden die KI-gewaehlten Aufruf-Parameter zusaetzlich gerendert.
 *
 * Datenquellen:
 *   - getScanResults() Response (durchgereicht ueber Props)
 *   - aiConfigs aus events-Endpoint
 */

import { useMemo, useState } from 'react';
import type { ScanResult } from '@/lib/api';

interface AiConfig {
  zap_scan_policy?: string;
  zap_spider_max_depth?: number;
  zap_ajax_spider_enabled?: boolean;
  zap_active_categories?: string[];
  zap_rate_req_per_sec?: number;
  zap_threads?: number;
  zap_spider_delay_ms?: number;
  zap_extra_urls?: string[];
  skip_tools?: string[];
  reasoning?: string;
}

interface DiscoveredHost {
  ip: string;
  fqdns?: string[];
}

interface Props {
  scanResults: ScanResult[];
  aiConfigs?: Record<string, AiConfig> | null;
  discoveredHosts?: DiscoveredHost[] | null;
}

const TRUNCATE_AT = 1000;
const PHASE_LABELS: Record<number, string> = {
  0: 'Phase 0 — DNS / Recon',
  1: 'Phase 1 — Tech / Ports',
  2: 'Phase 2 — Deep Scan',
  3: 'Phase 3 — Korrelation',
  4: 'Phase 4 — Report',
};
const PHASE_BADGE_CLS: Record<number, string> = {
  0: 'bg-blue-500/15 text-blue-300 ring-blue-500/30',
  1: 'bg-violet-500/15 text-violet-300 ring-violet-500/30',
  2: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30',
  3: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  4: 'bg-slate-500/15 text-slate-300 ring-slate-500/30',
};

// Tools die im Tool-Trace NICHT angezeigt werden — entweder Meta oder
// gehoeren zu KI-Costs.
function isExcludedTool(toolName: string): boolean {
  if (toolName.startsWith('ai_')) return true;       // AI-Debug-Entries
  if (toolName === 'report_cost') return true;
  if (toolName === 'phase3_correlation') return true;
  return false;
}

function fqdnFor(ip: string | null, hosts: DiscoveredHost[] | null | undefined): string {
  if (!ip) return '';
  const h = hosts?.find((d) => d.ip === ip);
  return h?.fqdns?.[0] ?? '';
}

function formatDuration(ms: number): string {
  if (!ms || ms < 0) return '—';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

function exitBadge(code: number): { label: string; cls: string } {
  if (code === 0) return { label: 'OK', cls: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30' };
  if (code === -1) return { label: 'TIMEOUT', cls: 'bg-red-500/15 text-red-300 ring-red-500/30' };
  if (code === 1) return { label: 'WARN', cls: 'bg-yellow-500/15 text-yellow-300 ring-yellow-500/30' };
  return { label: `EXIT ${code}`, cls: 'bg-amber-500/15 text-amber-300 ring-amber-500/30' };
}

// Aufruf-Parameter ableiten: wenn das Tool zur Phase-2-Config passt,
// zeigen wir die relevanten Felder als JSON-Block.
function relevantConfigForTool(
  toolName: string,
  cfg: AiConfig | undefined,
): Record<string, unknown> | null {
  if (!cfg) return null;
  // Prefix-Match: zap_*, zap_spider_*, zap_ajax_spider passen alle zu zap-Calls
  if (toolName.startsWith('zap')) {
    return {
      zap_scan_policy: cfg.zap_scan_policy,
      zap_spider_max_depth: cfg.zap_spider_max_depth,
      zap_ajax_spider_enabled: cfg.zap_ajax_spider_enabled,
      zap_active_categories: cfg.zap_active_categories,
      zap_rate_req_per_sec: cfg.zap_rate_req_per_sec,
      zap_threads: cfg.zap_threads,
      zap_spider_delay_ms: cfg.zap_spider_delay_ms,
      zap_extra_urls: cfg.zap_extra_urls,
    };
  }
  // Andere Tools: keine spezifische config — wir geben skip_tools zurueck
  // wenn der Tool-Name in skip_tools steht (Hinweis dass er nur zufaellig laeuft).
  if (cfg.skip_tools?.includes(toolName)) {
    return { skip_tools: cfg.skip_tools, hint: `${toolName} wurde fuer diesen Host eigentlich uebersprungen` };
  }
  return null;
}

export default function ToolTrace({ scanResults, aiConfigs, discoveredHosts }: Props) {
  const [filterPhase, setFilterPhase] = useState<string>('all');
  const [filterHost, setFilterHost] = useState<string>('all');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [fullOutput, setFullOutput] = useState<Set<string>>(new Set());

  // Filterbare Liste vorbereiten
  const visible = useMemo(() => {
    return scanResults
      .filter((r) => !isExcludedTool(r.toolName))
      .filter((r) => filterPhase === 'all' || String(r.phase) === filterPhase)
      .filter((r) => filterHost === 'all' || r.hostIp === filterHost)
      .sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
  }, [scanResults, filterPhase, filterHost]);

  // Eindeutige Hosts und Phasen aus den nicht-excluded results
  const { phases, hosts } = useMemo(() => {
    const phaseSet = new Set<number>();
    const hostSet = new Set<string>();
    for (const r of scanResults) {
      if (isExcludedTool(r.toolName)) continue;
      phaseSet.add(r.phase);
      if (r.hostIp) hostSet.add(r.hostIp);
    }
    return {
      phases: Array.from(phaseSet).sort((a, b) => a - b),
      hosts: Array.from(hostSet).sort(),
    };
  }, [scanResults]);

  if (visible.length === 0 && scanResults.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-sm text-slate-500">
        Keine Tool-Aufrufe verfügbar.
      </div>
    );
  }

  const totalAfterFilter = visible.length;
  const totalUnfiltered = scanResults.filter((r) => !isExcludedTool(r.toolName)).length;

  return (
    <div className="space-y-3">
      {/* Filter-Bar */}
      <div className="flex flex-wrap items-center gap-3 text-xs">
        <span className="text-slate-500">Filter:</span>
        <label className="flex items-center gap-1">
          <span className="text-slate-400">Phase</span>
          <select
            value={filterPhase}
            onChange={(e) => setFilterPhase(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200"
          >
            <option value="all">alle</option>
            {phases.map((p) => (
              <option key={p} value={p}>
                {PHASE_LABELS[p] ?? `Phase ${p}`}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1">
          <span className="text-slate-400">Host</span>
          <select
            value={filterHost}
            onChange={(e) => setFilterHost(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200 min-w-[14rem]"
          >
            <option value="all">alle</option>
            {hosts.map((ip) => {
              const fqdn = fqdnFor(ip, discoveredHosts);
              return (
                <option key={ip} value={ip}>
                  {ip}{fqdn ? ` (${fqdn})` : ''}
                </option>
              );
            })}
          </select>
        </label>
        <span className="ml-auto text-slate-500 tabular-nums">
          {totalAfterFilter} / {totalUnfiltered} Aufrufe
        </span>
      </div>

      {/* Liste */}
      {visible.length === 0 ? (
        <div className="rounded border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-500">
          Keine Tool-Aufrufe für diesen Filter.
        </div>
      ) : (
        <ul className="space-y-1.5">
          {visible.map((r) => {
            const isOpen = expandedId === r.id;
            const exit = exitBadge(r.exitCode);
            const phaseCls = PHASE_BADGE_CLS[r.phase] ?? PHASE_BADGE_CLS[4];
            const fqdn = fqdnFor(r.hostIp, discoveredHosts);
            const cfg = r.hostIp ? aiConfigs?.[r.hostIp] : undefined;
            const params = relevantConfigForTool(r.toolName, cfg);
            const ts = new Date(r.createdAt).toTimeString().slice(0, 8);

            const rawText = r.rawOutput ?? '';
            const isLong = rawText.length > TRUNCATE_AT;
            const showFull = fullOutput.has(r.id);
            const displayedRaw = isLong && !showFull ? rawText.slice(0, TRUNCATE_AT) + '\n…' : rawText;

            return (
              <li key={r.id} className="rounded border border-slate-800 bg-slate-950/40">
                <button
                  type="button"
                  onClick={() => setExpandedId(isOpen ? null : r.id)}
                  className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs hover:bg-slate-900/40"
                >
                  <span className={`shrink-0 rounded ring-1 px-1.5 py-0.5 font-mono text-[10px] ${phaseCls}`}>
                    P{r.phase}
                  </span>
                  <span className="font-mono text-slate-200 w-40 shrink-0 truncate">{r.toolName}</span>
                  <span className="font-mono text-slate-400 w-32 shrink-0 truncate">
                    {r.hostIp ?? '—'}
                  </span>
                  {fqdn && (
                    <span className="text-slate-500 truncate flex-1 hidden md:inline">{fqdn}</span>
                  )}
                  <span className={`shrink-0 rounded ring-1 px-1.5 py-0.5 font-mono text-[10px] ${exit.cls}`}>
                    {exit.label}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-400 tabular-nums w-14 text-right">
                    {formatDuration(r.durationMs)}
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500 tabular-nums">{ts}</span>
                  <span className="shrink-0 text-slate-500">{isOpen ? '▲' : '▼'}</span>
                </button>

                {isOpen && (
                  <div className="border-t border-slate-800 p-3 space-y-3">
                    {params && (
                      <div>
                        <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">
                          KI-Aufruf-Parameter
                        </div>
                        <pre className="text-[11px] font-mono text-cyan-200 bg-slate-950 rounded p-2 overflow-x-auto">
{JSON.stringify(params, null, 2)}
                        </pre>
                      </div>
                    )}
                    <div>
                      <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 flex items-center gap-2">
                        <span>Roher Output ({rawText.length.toLocaleString('de-DE')} Zeichen)</span>
                        {isLong && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setFullOutput((prev) => {
                                const next = new Set(prev);
                                if (next.has(r.id)) next.delete(r.id); else next.add(r.id);
                                return next;
                              });
                            }}
                            className="rounded bg-slate-800 hover:bg-slate-700 px-2 py-0.5 text-[10px] text-slate-200 normal-case tracking-normal"
                          >
                            {showFull ? 'Gekürzt anzeigen' : 'Vollständig anzeigen'}
                          </button>
                        )}
                      </div>
                      {rawText ? (
                        <pre className="text-[11px] font-mono text-slate-300 bg-slate-950 rounded p-2 max-h-[28rem] overflow-auto whitespace-pre-wrap break-all">
{displayedRaw}
                        </pre>
                      ) : (
                        <div className="text-[11px] text-slate-500 italic">Kein Output gespeichert.</div>
                      )}
                    </div>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
