import { statusMeta, TONE_COLOR, type StatusGlyph } from '@/lib/status';

// ── DS-Primitive: StatusChip (VEC-306, behebt H8) ───────────────
// Übersetzt technische Status-Codes in Kunden-Klartext und zeigt
// Ton-Farbe + Icon + Label. Farb-Unabhängigkeit (A11y §8): die
// Bedeutung steht immer im Label und im Icon, nie nur in der Farbe.

function GlyphIcon({ glyph, size }: { glyph: StatusGlyph; size: number }) {
  const common = {
    width: size, height: size, viewBox: '0 0 24 24', fill: 'none',
    stroke: 'currentColor', strokeWidth: 2, strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const, 'aria-hidden': true,
  };
  switch (glyph) {
    case 'spinner':
      return (
        <svg {...common} className="ds-spin">
          <path d="M21 12a9 9 0 1 1-6.219-8.56" />
        </svg>
      );
    case 'check':
      return <svg {...common}><path d="M20 6 9 17l-5-5" /></svg>;
    case 'clock':
      return <svg {...common}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>;
    case 'alert':
      return <svg {...common}><path d="M12 9v4" /><path d="M12 17h.01" /><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /></svg>;
    case 'cross':
      return <svg {...common}><circle cx="12" cy="12" r="9" /><path d="m15 9-6 6" /><path d="m9 9 6 6" /></svg>;
    case 'doc':
      return <svg {...common}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /><path d="M9 15h6" /></svg>;
    case 'dot':
    default:
      return <svg {...common} fill="currentColor" stroke="none"><circle cx="12" cy="12" r="5" /></svg>;
  }
}

export default function StatusChip({
  status,
  size = 'md',
  className = '',
}: {
  status: string | null | undefined;
  size?: 'sm' | 'md';
  className?: string;
}) {
  const meta = statusMeta(status);
  const color = TONE_COLOR[meta.tone];
  const iconSize = size === 'sm' ? 12 : 14;
  const pad = size === 'sm' ? 'px-2 py-0.5 text-[11px] gap-1' : 'px-2.5 py-1 text-xs gap-1.5';

  return (
    <span
      className={`inline-flex items-center font-medium rounded-md whitespace-nowrap ${pad} ${className}`}
      style={{
        color,
        backgroundColor: `color-mix(in srgb, ${color} 14%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 28%, transparent)`,
      }}
    >
      {meta.active ? (
        <span className="relative inline-flex" style={{ width: iconSize, height: iconSize }}>
          <GlyphIcon glyph={meta.glyph} size={iconSize} />
        </span>
      ) : (
        <GlyphIcon glyph={meta.glyph} size={iconSize} />
      )}
      <span>{meta.label}</span>
    </span>
  );
}
