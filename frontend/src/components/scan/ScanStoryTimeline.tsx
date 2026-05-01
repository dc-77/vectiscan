'use client';

/**
 * ScanStoryTimeline — chronologische Erzaehlung des Scans:
 * KI-Decision (◉) -> Tool-Start (⚙) -> Skip (⊘) -> Finding (⚠).
 *
 * Datenquellen:
 *   - aiStrategy.hosts[]: scan/skip-Entscheidungen (KI #1)
 *   - aiConfigs (Map IP -> config): Phase-2-Config-Decisions (KI #3)
 *   - toolOutputs: chronologische Tool-Starts mit Summary
 */

interface AiHost {
  ip: string;
  action?: 'scan' | 'skip';
  priority?: number | null;
  reasoning?: string;
}

interface AiConfig {
  zap_scan_policy?: string;
  skip_tools?: string[];
  reasoning?: string;
}

interface ToolOutput {
  tool: string;
  host: string;
  summary?: string;
  ts?: number | string;
}

interface Props {
  aiStrategy?: { strategy_notes?: string; hosts?: AiHost[] } | null;
  aiConfigs?: Record<string, AiConfig> | null;
  toolOutputs?: ToolOutput[] | null;
  discoveredHosts?: Array<{ ip: string; fqdns?: string[] }> | null;
}

type Item = {
  type: 'strategy' | 'targeting' | 'skip' | 'config' | 'tool';
  ts: number;
  title: string;
  detail?: string;
  badge?: string;
};

function fqdnFor(ip: string, hosts: Array<{ ip: string; fqdns?: string[] }> | null | undefined): string {
  return hosts?.find((h) => h.ip === ip)?.fqdns?.[0] ?? ip;
}

const ICONS: Record<string, { icon: string; ring: string; text: string }> = {
  strategy:  { icon: '◉', ring: 'ring-cyan-500/40 bg-cyan-500/10',     text: 'text-cyan-300' },
  targeting: { icon: '◉', ring: 'ring-cyan-500/30 bg-cyan-500/5',      text: 'text-cyan-300' },
  skip:      { icon: '⊘', ring: 'ring-slate-700 bg-slate-900',          text: 'text-slate-400' },
  config:    { icon: '⚙', ring: 'ring-purple-500/30 bg-purple-500/5',  text: 'text-purple-300' },
  tool:      { icon: '⚡', ring: 'ring-emerald-500/30 bg-emerald-500/5', text: 'text-emerald-300' },
};

export default function ScanStoryTimeline({
  aiStrategy,
  aiConfigs,
  toolOutputs,
  discoveredHosts,
}: Props) {
  const items: Item[] = [];
  // Wir haben keinen echten KI-Decision-Timestamp im Payload, nur Tool-Output-TS.
  // Daher: Strategy + Targetings + Configs als ein Block ganz oben (logische Reihenfolge),
  // dann Tool-Outputs chronologisch nach unten.
  let baseTs = 0;
  if (toolOutputs && toolOutputs.length > 0) {
    const first = toolOutputs[0]?.ts;
    if (typeof first === 'number') baseTs = first;
    else if (typeof first === 'string') baseTs = new Date(first).getTime();
  }
  if (!baseTs) baseTs = Date.now();

  if (aiStrategy?.strategy_notes) {
    items.push({
      type: 'strategy',
      ts: baseTs - 1000,
      title: 'Scan-Strategie',
      detail: aiStrategy.strategy_notes,
      badge: 'KI #1',
    });
  }

  (aiStrategy?.hosts ?? []).forEach((h) => {
    items.push({
      type: h.action === 'skip' ? 'skip' : 'targeting',
      ts: baseTs - 800,
      title: `${h.action === 'skip' ? 'Skip' : 'Targeting'} ${fqdnFor(h.ip, discoveredHosts)}${
        h.priority ? `  [P${h.priority}]` : ''
      }`,
      detail: h.reasoning,
      badge: 'KI #1',
    });
  });

  Object.entries(aiConfigs ?? {}).forEach(([ip, cfg]) => {
    const skipText = (cfg.skip_tools ?? []).length > 0 ? ` skip:[${(cfg.skip_tools ?? []).join(', ')}]` : '';
    items.push({
      type: 'config',
      ts: baseTs - 500,
      title: `${fqdnFor(ip, discoveredHosts)} — policy=${cfg.zap_scan_policy ?? 'standard'}${skipText}`,
      detail: cfg.reasoning,
      badge: 'KI #3',
    });
  });

  (toolOutputs ?? []).forEach((t) => {
    const ts = typeof t.ts === 'number' ? t.ts : t.ts ? new Date(t.ts).getTime() : baseTs;
    items.push({
      type: 'tool',
      ts,
      title: `${t.tool} → ${fqdnFor(t.host, discoveredHosts)}`,
      detail: t.summary,
    });
  });

  if (items.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-sm text-slate-500">
        Noch keine Scan-Story verfügbar.
      </div>
    );
  }

  // Sort by timestamp ascending — older events first
  items.sort((a, b) => a.ts - b.ts);

  return (
    <ol className="relative ml-2 border-l border-slate-800 space-y-4 py-1">
      {items.map((it, idx) => {
        const style = ICONS[it.type] ?? ICONS.tool;
        const time = new Date(it.ts).toTimeString().slice(0, 8);
        return (
          <li key={`${it.type}-${idx}`} className="ml-6">
            <span
              className={`absolute -left-3 inline-flex h-6 w-6 items-center justify-center rounded-full ring-2 ${style.ring}`}
              aria-hidden
            >
              <span className={`text-sm ${style.text}`}>{style.icon}</span>
            </span>
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1">
                <div className="flex items-baseline gap-2">
                  <span className={`text-sm font-medium ${style.text}`}>{it.title}</span>
                  {it.badge && (
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                      {it.badge}
                    </span>
                  )}
                </div>
                {it.detail && (
                  <p className="mt-1 text-xs leading-relaxed text-slate-400 whitespace-pre-wrap">
                    {it.detail}
                  </p>
                )}
              </div>
              <time className="shrink-0 font-mono text-[10px] text-slate-500 tabular-nums">{time}</time>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
