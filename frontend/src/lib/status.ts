// ─────────────────────────────────────────────────────────────
// Kanonisches Status-Mapping (VEC-306 DS, behebt H8)
// Technische Order-/Scan-Status → Kunden-Klartext + Ton + Icon.
// Einzige Wahrheit für StatusChip & Co. — keine zweite Status-Sprache.
// Töne referenzieren CSS-Vars aus globals.css (Farb-Unabhängigkeit:
// der Chip trägt zusätzlich Icon + Label, nie nur Farbe).
// ─────────────────────────────────────────────────────────────

export type StatusTone = 'active' | 'success' | 'info' | 'warn' | 'danger' | 'neutral';

/** Icon-Glyph-Schlüssel — wird in StatusChip auf ein Inline-SVG gemappt. */
export type StatusGlyph = 'spinner' | 'check' | 'clock' | 'alert' | 'cross' | 'dot' | 'doc';

export interface StatusMeta {
  /** Kunden-Klartext (deutsch, kein technischer Code). */
  label: string;
  tone: StatusTone;
  glyph: StatusGlyph;
  /** true = laufender Prozess (Chip zeigt Puls-Indikator). */
  active?: boolean;
}

export const TONE_COLOR: Record<StatusTone, string> = {
  active:  'var(--tone-active)',
  success: 'var(--tone-success)',
  info:    'var(--tone-info)',
  warn:    'var(--tone-warn)',
  danger:  'var(--tone-danger)',
  neutral: 'var(--tone-neutral)',
};

const STATUS_META: Record<string, StatusMeta> = {
  // ── Order-Lifecycle vor dem Scan ──
  created:               { label: 'Erstellt',           tone: 'neutral', glyph: 'dot' },
  precheck_running:      { label: 'Wird vorbereitet',   tone: 'active',  glyph: 'spinner', active: true },
  'precheck-pending':    { label: 'Wird vorbereitet',   tone: 'active',  glyph: 'spinner', active: true },
  precheck_pending:      { label: 'Wird vorbereitet',   tone: 'active',  glyph: 'spinner', active: true },
  pending_target_review: { label: 'Wird geprüft',       tone: 'info',    glyph: 'clock' },
  verification_pending:  { label: 'Verifizierung nötig', tone: 'warn',   glyph: 'alert' },
  verified:              { label: 'Verifiziert',        tone: 'info',    glyph: 'check' },
  'scan-pending':        { label: 'In Warteschlange',   tone: 'info',    glyph: 'clock' },
  scan_pending:          { label: 'In Warteschlange',   tone: 'info',    glyph: 'clock' },
  queued:                { label: 'In Warteschlange',   tone: 'info',    glyph: 'clock' },
  approved:              { label: 'Freigegeben',        tone: 'info',    glyph: 'check' },
  rejected:              { label: 'Abgelehnt',          tone: 'danger',  glyph: 'cross' },

  // ── Scan läuft ──
  scanning:        { label: 'Scan läuft',        tone: 'active', glyph: 'spinner', active: true },
  passive_intel:   { label: 'Aufklärung läuft',  tone: 'active', glyph: 'spinner', active: true },
  dns_recon:       { label: 'DNS-Analyse',       tone: 'active', glyph: 'spinner', active: true },
  scan_phase1:     { label: 'Scan läuft (1/3)',  tone: 'active', glyph: 'spinner', active: true },
  scan_phase2:     { label: 'Scan läuft (2/3)',  tone: 'active', glyph: 'spinner', active: true },
  scan_phase3:     { label: 'Scan läuft (3/3)',  tone: 'active', glyph: 'spinner', active: true },
  scan_complete:   { label: 'Scan abgeschlossen', tone: 'info',  glyph: 'check' },

  // ── Report ──
  pending_review:    { label: 'Wartet auf Freigabe', tone: 'info',    glyph: 'clock' },
  report_generating: { label: 'Bericht wird erstellt', tone: 'active', glyph: 'spinner', active: true },
  report_complete:   { label: 'Bericht fertig',     tone: 'success', glyph: 'doc' },
  delivered:         { label: 'Zugestellt',         tone: 'success', glyph: 'check' },

  // ── Terminalzustände ──
  failed:     { label: 'Fehlgeschlagen', tone: 'danger',  glyph: 'cross' },
  cancelled:  { label: 'Abgebrochen',    tone: 'neutral', glyph: 'dot' },
};

const FALLBACK: StatusMeta = { label: 'Unbekannt', tone: 'neutral', glyph: 'dot' };

/** Liefert die Klartext-Metadaten zu einem technischen Status-Code. */
export function statusMeta(status: string | null | undefined): StatusMeta {
  if (!status) return FALLBACK;
  const key = String(status).trim();
  return STATUS_META[key] ?? STATUS_META[key.toLowerCase()] ?? FALLBACK;
}

/** Nur das Kunden-Label — Drop-in-Ersatz für rohe Status-Codes. */
export function statusLabel(status: string | null | undefined): string {
  return statusMeta(status).label;
}
