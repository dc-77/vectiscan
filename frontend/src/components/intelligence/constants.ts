// ─── Design Tokens ─────────────────────────────────────
export const COLORS = {
  base: '#0a0f1e',
  panel: '#0f172a',
  border: '#1E3A5F',
  borderDim: 'rgba(30,58,95,0.5)',
  cyan: '#38BDF8',
  cyanDim: '#7DD3FC',
  cyanGlow: 'rgba(56,189,248,0.4)',
  amber: '#EAB308',
  amberDim: '#D97706',
  amberGlow: 'rgba(234,179,8,0.3)',
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
