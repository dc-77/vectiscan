/** CVSS score → human-readable German label with urgency */
export function cvssLabel(score: number): { text: string; urgency: string } {
  if (score >= 9.0) return { text: 'Kritisch', urgency: 'sofort handeln' };
  if (score >= 7.0) return { text: 'Hoch', urgency: 'innerhalb einer Woche' };
  if (score >= 4.0) return { text: 'Mittel', urgency: 'innerhalb von 30 Tagen' };
  if (score > 0) return { text: 'Niedrig', urgency: 'bei Gelegenheit' };
  return { text: 'Information', urgency: '' };
}

/** Format duration in minutes → human-readable German */
export function formatDuration(minutes: number): string {
  if (minutes < 1) return '< 1 Min';
  if (minutes < 60) return `${Math.round(minutes)} Min`;
  const h = Math.floor(minutes / 60);
  const m = Math.round(minutes % 60);
  if (h >= 24) {
    const d = Math.floor(h / 24);
    return `~${d} Tag${d > 1 ? 'e' : ''}`;
  }
  return m > 0 ? `${h} Std ${m} Min` : `${h} Std`;
}

/** Internal status → German display label */
export const STATUS_LABELS: Record<string, string> = {
  verification_pending: 'Verifizierung',
  created: 'Erstellt',
  queued: 'In Warteschlange',
  scanning: 'Startet...',
  passive_intel: 'Passive Aufklärung',
  dns_recon: 'DNS-Analyse',
  scan_phase1: 'Phase 1 — Port-Analyse',
  scan_phase2: 'Phase 2 — Schwachstellen',
  scan_phase3: 'Phase 3 — KI-Korrelation',
  scan_complete: 'Scan abgeschlossen',
  pending_review: 'Wartet auf Prüfung',
  approved: 'Genehmigt',
  rejected: 'Abgelehnt',
  report_generating: 'Report wird erstellt...',
  report_complete: 'Fertig',
  delivered: 'Zugestellt',
  failed: 'Fehlgeschlagen',
  cancelled: 'Abgebrochen',
  verified: 'Verifiziert',
};
