/**
 * SeverityCounts — compact monospace severity counters replacing the rainbow bar.
 * Only CRITICAL and HIGH get color emphasis; everything else is muted.
 */

const SEVERITY_KEYS = [
  { key: 'CRITICAL', short: 'C', alert: true },
  { key: 'HIGH',     short: 'H', alert: true },
  { key: 'MEDIUM',   short: 'M', alert: false },
  { key: 'LOW',      short: 'L', alert: false },
  { key: 'INFO',     short: 'I', alert: false },
] as const;

interface SeverityCountsProps {
  counts: Record<string, number>;
}

export default function SeverityCounts({ counts }: SeverityCountsProps) {
  const entries = SEVERITY_KEYS
    .map(({ key, short, alert }) => ({ key, short, alert, count: counts[key] || 0 }))
    .filter(e => e.count > 0);

  if (entries.length === 0) return null;

  return (
    <span className="inline-flex gap-2 font-mono text-xs tabular-nums">
      {entries.map(({ key, short, alert, count }) => (
        <span key={key} className={alert ? (key === 'CRITICAL' ? 'text-red-400' : 'text-red-400/60') : 'text-slate-500'}>
          {count}{short}
        </span>
      ))}
    </span>
  );
}
