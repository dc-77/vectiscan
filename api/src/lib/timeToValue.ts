/**
 * VEC-87 (PA-7) — Onboarding-Time-to-Value-Messpunkt.
 *
 * Liefert die objektiv prüfbare Kennzahl für AC3: die Spanne zwischen
 * Kunden-Registrierung (customers.created_at) und dem ERSTEN
 * `report_complete` dieses Kunden. Reine Funktion ohne DB/IO, damit sie
 * CI-tauglich unit-getestet werden kann; die DB-Abfrage + das Schreiben
 * des Audit-Events liegen im Aufrufer (ws-manager.handleReportComplete).
 */

export interface TimeToValueInput {
  /** customers.created_at — Registrierungszeitpunkt. */
  registeredAt: Date;
  /** Zeitpunkt des report_complete-Events. */
  completedAt: Date;
  /**
   * Anzahl bereits abgeschlossener Reports (report_complete/delivered)
   * dieses Kunden, OHNE den aktuellen Auftrag. 0 ⇒ dies ist der erste.
   */
  priorCompletedCount: number;
}

export interface TimeToValueResult {
  registeredAt: string;
  completedAt: string;
  /** Sekunden von Registrierung bis erstem report_complete (>= 0). */
  ttvSeconds: number;
}

/**
 * Berechnet den Time-to-Value-Messpunkt. Gibt `null` zurück, wenn dies
 * NICHT der erste abgeschlossene Report des Kunden ist (dann ist die
 * Onboarding-Kennzahl bereits erfasst und darf nicht überschrieben werden).
 */
export function computeTimeToValue(input: TimeToValueInput): TimeToValueResult | null {
  if (input.priorCompletedCount > 0) {
    return null;
  }

  const registeredMs = input.registeredAt.getTime();
  const completedMs = input.completedAt.getTime();

  // Defensive: niemals negativ (Uhr-Drift / Datenanomalie) — auf 0 klemmen,
  // damit die Kennzahl auswertbar bleibt statt das Event zu verwerfen.
  const ttvSeconds = Math.max(0, Math.round((completedMs - registeredMs) / 1000));

  return {
    registeredAt: input.registeredAt.toISOString(),
    completedAt: input.completedAt.toISOString(),
    ttvSeconds,
  };
}
