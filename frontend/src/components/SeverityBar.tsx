/**
 * SeverityBar — stacked horizontal bar showing finding severity distribution.
 * Uses VectiScan CI severity colors from branding.py.
 */

const SEVERITY_CONFIG = [
  { key: 'CRITICAL', color: '#DC2626', label: 'Critical' },
  { key: 'HIGH',     color: '#EA580C', label: 'High' },
  { key: 'MEDIUM',   color: '#CA8A04', label: 'Medium' },
  { key: 'LOW',      color: '#16A34A', label: 'Low' },
  { key: 'INFO',     color: '#2563EB', label: 'Info' },
] as const;

interface SeverityBarProps {
  counts: Record<string, number>;
  compact?: boolean;
}

export default function SeverityBar({ counts, compact = false }: SeverityBarProps) {
  const total = SEVERITY_CONFIG.reduce((sum, s) => sum + (counts[s.key] || 0), 0);
  if (total === 0) return null;

  const height = compact ? 'h-1' : 'h-2';

  return (
    <div className="flex items-center gap-2 w-full">
      <div className={`flex ${height} rounded-full overflow-hidden flex-1 bg-gray-800`}>
        {SEVERITY_CONFIG.map(({ key, color }) => {
          const count = counts[key] || 0;
          if (count === 0) return null;
          const pct = (count / total) * 100;
          return (
            <div
              key={key}
              style={{ width: `${pct}%`, backgroundColor: color }}
              className="transition-all duration-500"
              title={`${key}: ${count}`}
            />
          );
        })}
      </div>
      {!compact && (
        <span className="text-xs text-gray-500 shrink-0 tabular-nums">{total}</span>
      )}
    </div>
  );
}

export { SEVERITY_CONFIG };
