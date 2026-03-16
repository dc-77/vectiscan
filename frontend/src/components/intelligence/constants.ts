// ─── Design Tokens ─────────────────────────────────────
export const COLORS = {
  base: '#0C1222',
  panel: '#0f172a',
  border: '#1E3A5F',
  borderDim: 'rgba(30,58,95,0.3)',
  // Primary accent — unified blue
  cyan: '#3b82f6',
  cyanDim: '#60a5fa',
  cyanGlow: 'rgba(59,130,246,0.4)',
  // Alert accent — kept for scanning states
  amber: '#3b82f6',      // mapped to blue (was amber)
  amberDim: '#60a5fa',
  amberGlow: 'rgba(59,130,246,0.3)',
  green: '#16A34A',
  greenDim: '#22C55E',
  red: '#EF4444',
  redDim: '#F87171',
  redGlow: 'rgba(239,68,68,0.4)',
  gray: '#64748B',
  grayDim: '#475569',
  white: '#E2E8F0',
  textDim: '#94A3B8',
} as const;

export const STATUS_COLORS: Record<string, string> = {
  discovered: COLORS.cyan,
  scanning: COLORS.amber,
  scanned: COLORS.green,
  skipped: COLORS.gray,
};

export const TIMING = {
  radarSweep: 4000,
  particleSpeed: 2500,
  dataStreamInterval: 350,
  dataStreamBurstInterval: 150,
  burstProbability: 0.04,
  glitchDuration: 150,
  counterRollDuration: 600,
  burstCooldown: 2000,
} as const;

// ─── Shared Types ──────────────────────────────────────
export interface HostNode {
  ip: string;
  fqdns: string[];
  status: 'discovered' | 'scanning' | 'scanned' | 'skipped';
  reasoning?: string;
}

export interface ToolOutputEntry {
  tool: string;
  host: string;
  summary: string;
  ts: number;
}

/** Get display name for a host — prefer FQDN over IP */
export function hostDisplayName(host: HostNode | { ip: string; fqdns?: string[] }): string {
  const fqdn = host.fqdns?.[0]?.replace(/\.$/, '');
  return fqdn || host.ip;
}

/** Truncate a string to max length with .. suffix */
export function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 2) + '..' : s;
}
