'use client';

interface ShieldProps {
  size?: number;
  variant?: 'teal' | 'dark';
  className?: string;
}

/**
 * VectiScan Shield Logo — Doppelkontur mit V.
 *
 * Stroke weights adapt for small sizes (≤32px → thicker strokes).
 * See docs/brand.html section 07 "Größentest".
 */
export function VectiScanShield({ size = 48, variant = 'teal', className = '' }: ShieldProps) {
  const isSmall = size <= 32;
  const color = variant === 'teal' ? '#2DD4BF' : '#0F172A';
  const ghostOpacity = variant === 'teal' ? 0.35 : 0.2;

  // Stroke widths adapt to size
  const outerStroke = isSmall ? (size <= 20 ? 10 : size <= 24 ? 8 : 6) : 3;
  const innerStroke = isSmall ? (size <= 20 ? 14 : size <= 24 ? 10 : 8) : 5;
  const vStroke = isSmall ? (size <= 20 ? 22 : size <= 24 ? 18 : 16) : 12;

  return (
    <svg
      width={size}
      height={size * 1.05}
      viewBox="0 0 200 210"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      {/* Outer ghost contour */}
      <path
        d="M100 8 L178 48 L178 116 C178 156 144 186 100 200 C56 186 22 156 22 116 L22 48 Z"
        fill="none"
        stroke={color}
        strokeWidth={outerStroke}
        opacity={ghostOpacity}
      />
      {/* Inner contour */}
      <path
        d="M100 22 L166 56 L166 110 C166 146 138 174 100 186 C62 174 34 146 34 110 L34 56 Z"
        fill="none"
        stroke={color}
        strokeWidth={innerStroke}
      />
      {/* V mark */}
      <path
        d="M70 74 L100 140 L130 74"
        fill="none"
        stroke={color}
        strokeWidth={vStroke}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

interface LogoProps {
  className?: string;
  size?: number;
  showWordmark?: boolean;
}

/**
 * Full VectiScan Logo: Shield + Wordmark.
 *
 * Wordmark: "vectiscan" in Inter Bold 700, lowercase.
 * "vecti" in text color, "scan" in Teal.
 */
export default function VectiScanLogo({ className = '', size = 48, showWordmark = true }: LogoProps) {
  return (
    <div className={`flex items-center justify-center gap-3 ${className}`}>
      <VectiScanShield size={size} variant="teal" />
      {showWordmark && (
        <span className="text-2xl font-bold tracking-tight leading-none" style={{ letterSpacing: '-1px' }}>
          <span style={{ color: '#F8FAFC' }}>vecti</span>
          <span style={{ color: '#2DD4BF' }}>scan</span>
        </span>
      )}
    </div>
  );
}
