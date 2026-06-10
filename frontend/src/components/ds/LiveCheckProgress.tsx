'use client';

// ── DS-Komponente: LiveCheckProgress (VEC-366) ───────────────────
// Schmale Fortschrittszeile für den SofortScan: "N von Total Checks"
// + animierte Progress-Bar. prefers-reduced-motion respektiert.

interface LiveCheckProgressProps {
  done: number;
  total: number;
  className?: string;
}

export default function LiveCheckProgress({ done, total, className = '' }: LiveCheckProgressProps) {
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  return (
    <div className={`${className}`} role="progressbar" aria-valuenow={done} aria-valuemax={total} aria-label={`${done} von ${total} Checks abgeschlossen`}>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-sm text-slate-400">
          {done} von {total} Checks abgeschlossen
        </span>
        <span className="text-xs text-slate-500 tabular-nums">{pct}%</span>
      </div>
      <div className="h-1 rounded-full overflow-hidden" style={{ background: 'rgba(45,212,191,0.12)' }}>
        <div
          className="h-full rounded-full motion-reduce:transition-none"
          style={{
            width: `${pct}%`,
            background: 'var(--tone-active)',
            transition: 'width 0.3s ease',
          }}
        />
      </div>
    </div>
  );
}
