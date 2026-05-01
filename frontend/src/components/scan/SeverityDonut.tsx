'use client';

/**
 * SeverityDonut — Pure-SVG Donut-Chart fuer die Severity-Verteilung eines Reports.
 *
 * Datenquelle: `audit_severity_counts` aus /api/orders/:id/findings
 * (Migration 016/018-Trigger). Fallback auf `severity_counts` aus
 * findings_data wenn Audit-Spalte null ist (alte Reports).
 */

interface Counts {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  info?: number;
}

const SEGMENTS: Array<{ key: keyof Counts; label: string; color: string }> = [
  { key: 'critical', label: 'Critical', color: '#DC2626' }, // red-600
  { key: 'high',     label: 'High',     color: '#F97316' }, // orange-500
  { key: 'medium',   label: 'Medium',   color: '#EAB308' }, // yellow-500
  { key: 'low',      label: 'Low',      color: '#3B82F6' }, // blue-500
  { key: 'info',     label: 'Info',     color: '#64748B' }, // slate-500
];

interface Props {
  counts: Counts | null | undefined;
  size?: number;
  thickness?: number;
}

export default function SeverityDonut({ counts, size = 140, thickness = 18 }: Props) {
  // Counts can be either lower-case (audit_severity_counts) or upper-case
  // (legacy severity_counts in findings_data). Normalize zu lower.
  const norm: Required<Counts> = {
    critical: Number(counts?.critical ?? (counts as Record<string, number> | undefined)?.CRITICAL ?? 0),
    high:     Number(counts?.high     ?? (counts as Record<string, number> | undefined)?.HIGH     ?? 0),
    medium:   Number(counts?.medium   ?? (counts as Record<string, number> | undefined)?.MEDIUM   ?? 0),
    low:      Number(counts?.low      ?? (counts as Record<string, number> | undefined)?.LOW      ?? 0),
    info:     Number(counts?.info     ?? (counts as Record<string, number> | undefined)?.INFO     ?? 0),
  };
  const total = norm.critical + norm.high + norm.medium + norm.low + norm.info;

  const center = size / 2;
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;

  // Wenn 0 Findings: einen vollen Slate-Ring zeigen mit "0" in der Mitte.
  if (total === 0) {
    return (
      <div className="inline-flex items-center gap-4">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-label="Keine Findings">
          <circle cx={center} cy={center} r={radius} fill="none" stroke="#1E293B" strokeWidth={thickness} />
          <text x={center} y={center} textAnchor="middle" dominantBaseline="central"
                className="fill-slate-400" fontSize={size * 0.18} fontWeight="600">0</text>
        </svg>
        <ul className="space-y-1 text-xs text-slate-400">
          {SEGMENTS.map((s) => (
            <li key={s.key} className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-full" style={{ background: s.color }} />
              {s.label} <span className="tabular-nums text-slate-500">0</span>
            </li>
          ))}
        </ul>
      </div>
    );
  }

  // Berechne Segmente: jeder Slice = (count / total) * circumference
  let offset = 0;
  const slices = SEGMENTS.map((s) => {
    const value = norm[s.key] || 0;
    const length = total > 0 ? (value / total) * circumference : 0;
    const node = (
      <circle
        key={s.key}
        cx={center}
        cy={center}
        r={radius}
        fill="none"
        stroke={s.color}
        strokeWidth={thickness}
        strokeDasharray={`${length} ${circumference - length}`}
        strokeDashoffset={-offset}
        // Drehe so dass das erste Segment am Top startet (12 Uhr).
        transform={`rotate(-90 ${center} ${center})`}
      />
    );
    offset += length;
    return { node, value, ...s };
  });

  return (
    <div className="inline-flex items-center gap-4">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-label={`${total} Findings`}>
        {/* Background-Ring damit die Naht zwischen Segmenten nicht durchscheint */}
        <circle cx={center} cy={center} r={radius} fill="none" stroke="#0F172A" strokeWidth={thickness} />
        {slices.map((s) => s.node)}
        <text x={center} y={center - size * 0.04} textAnchor="middle" dominantBaseline="central"
              className="fill-white" fontSize={size * 0.22} fontWeight="700">
          {total}
        </text>
        <text x={center} y={center + size * 0.13} textAnchor="middle" dominantBaseline="central"
              className="fill-slate-400" fontSize={size * 0.09} fontWeight="500">
          Findings
        </text>
      </svg>
      <ul className="space-y-1 text-xs">
        {slices.map((s) => (
          <li key={s.key} className="flex items-center gap-2 tabular-nums">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: s.color }} />
            <span className="text-slate-300 w-16">{s.label}</span>
            <span className={s.value > 0 ? 'text-white font-semibold' : 'text-slate-600'}>{s.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
