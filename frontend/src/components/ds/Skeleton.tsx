// ── DS-Primitive: Skeleton (VEC-306, behebt H9) ─────────────────
// Ladeplatzhalter statt "Lade…"-Text. Shimmer via .ds-skeleton
// (globals.css), respektiert prefers-reduced-motion (global guard).

export function SkeletonBox({ className = '', style }: { className?: string; style?: React.CSSProperties }) {
  return <div className={`ds-skeleton ${className}`} style={style} aria-hidden />;
}

/** Eine Liste aus n Karten-Zeilen (Dashboard/Scans-Liste). */
export function SkeletonList({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-4" role="status" aria-label="Lädt…">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="rounded-lg p-5"
          style={{ backgroundColor: 'var(--surface)', border: '1px solid var(--border-muted)' }}
        >
          <div className="flex items-center justify-between gap-2 mb-3">
            <SkeletonBox className="h-4 w-40" />
            <SkeletonBox className="h-5 w-20" />
          </div>
          <SkeletonBox className="h-3 w-full max-w-xs mb-2" />
          <SkeletonBox className="h-3 w-1/2" />
        </div>
      ))}
    </div>
  );
}

/** KPI-/Übersichtskarten (Dashboard-Snapshot). */
export function SkeletonCards({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3" role="status" aria-label="Lädt…">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded-xl p-4" style={{ backgroundColor: 'var(--surface)' }}>
          <SkeletonBox className="h-2.5 w-16 mb-3" />
          <SkeletonBox className="h-7 w-12" />
        </div>
      ))}
    </div>
  );
}

/** Detailseite (Order-Detail/Report). */
export function SkeletonDetail() {
  return (
    <div className="space-y-4" role="status" aria-label="Lädt…">
      <SkeletonBox className="h-7 w-1/3" />
      <SkeletonCards count={4} />
      <SkeletonBox className="h-48 w-full" />
    </div>
  );
}

export default SkeletonList;
