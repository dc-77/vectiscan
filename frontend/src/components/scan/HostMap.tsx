'use client';

/**
 * HostMap — Grid mit einer Karte pro Host. Zeigt KI-Targeting-Decision
 * (Priority-Badge P1/P2/P3 + scan/skip-Status) und das Reasoning auf
 * einen Klick / Hover.
 *
 * Datenquellen (alle aus /api/orders/:id/events):
 *   - aiStrategy.hosts[]: { ip, action, priority, reasoning, scan_hints }
 *   - discoveredHosts: Fallback wenn keine AI-Strategy vorliegt
 */

interface AiHost {
  ip: string;
  action?: 'scan' | 'skip';
  priority?: number | null;
  reasoning?: string;
  scan_hints?: Record<string, unknown>;
}

interface DiscoveredHost {
  ip: string;
  fqdns?: string[];
  hostname?: string;
}

interface Props {
  aiHosts: AiHost[] | null | undefined;
  discoveredHosts: DiscoveredHost[] | null | undefined;
  strategyNotes?: string | null;
}

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

export default function HostMap({ aiHosts, discoveredHosts, strategyNotes }: Props) {
  // Wenn keine aiStrategy vorliegt: simple Liste der discovered hosts
  if (!aiHosts || aiHosts.length === 0) {
    if (!discoveredHosts || discoveredHosts.length === 0) {
      return (
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-sm text-slate-500">
          Noch keine Host-Daten verfügbar.
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

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 items-start">
          {aiHosts.map((h) => {
            const isSkip = h.action === 'skip';
            const fqdn = fqdnFor(h, discoveredHosts);
            const prio = h.priority ? PRIORITY_STYLES[String(h.priority)] : null;

            return (
              <div
                key={h.ip}
                className={`rounded-lg border p-3 ${
                  isSkip
                    ? 'border-slate-800 bg-slate-950/30'
                    : 'border-slate-700 bg-slate-900/60'
                }`}
              >
                <div className="flex items-center gap-2">
                  {prio && (
                    <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${prio.badge}`}>
                      {prio.label}
                    </span>
                  )}
                  <span
                    className={`text-base ${isSkip ? 'text-slate-500' : 'text-emerald-400'}`}
                    aria-label={isSkip ? 'skipped' : 'scanned'}
                    title={isSkip ? 'Skipped' : 'Scanned'}
                  >
                    {isSkip ? '⊘' : '✓'}
                  </span>
                  <span className="font-mono text-xs text-cyan-300 truncate flex-1">{h.ip}</span>
                </div>
                {fqdn && (
                  <div className={`mt-1 text-xs truncate ${isSkip ? 'text-slate-600' : 'text-slate-300'}`}>
                    {fqdn}
                  </div>
                )}
                {h.reasoning && (
                  <div
                    className={`mt-2 text-xs leading-snug ${
                      isSkip ? 'text-slate-500' : 'text-slate-400'
                    }`}
                  >
                    {h.reasoning}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
