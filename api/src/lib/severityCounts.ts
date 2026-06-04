// ============================================================
// VEC-123: Severity-Zähler-Drift härten
// ============================================================
// Single source of truth fuer die Severity-Verteilung eines Reports.
//
// Hintergrund:
//   - reports.findings_data->'severity_counts' ist ein EINGEBETTETES,
//     handpflegbares Objekt (UPPER-case keys: {CRITICAL, HIGH, ...}), das
//     der Report-Worker schreibt. Es kann vom tatsaechlich gelisteten
//     findings_data->'findings'-Array DRIFTEN (z.B. wenn Selection/Policy
//     Findings nach der Zaehlung trimmt). In der Demo war das 12 vs. 11.
//   - reports.severity_counts (Spalte, Migration 016/018) wird per
//     BEFORE-INSERT/UPDATE-Trigger AUS findings_data->'findings' berechnet
//     (lower-case keys: {critical, high, ...}) und ist damit AUTORITATIV.
//
// Diese Helfer liefern die Severity-Verteilung IMMER aus der autoritativen
// Quelle und normalisieren sie in die kanonische UPPER-case-Form, die API
// und Frontend seit jeher ausliefern/erwarten (SeverityCounts.tsx liest
// counts['CRITICAL'] etc.). Dadurch bleibt die Drift unmoeglich, ohne die
// Antwort-Form fuer korrekte Reports zu aendern.
// ============================================================

export const SEVERITY_KEYS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type SeverityKey = (typeof SEVERITY_KEYS)[number];
export type SeverityCounts = Record<SeverityKey, number>;

function emptyCounts(): SeverityCounts {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

function toCount(v: unknown): number {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
  return 0;
}

/**
 * Normalisiert die autoritative reports.severity_counts-Spalte (lower-case,
 * trigger-berechnet) in die kanonische UPPER-case-Form. Unbekannte Severities
 * werden ignoriert, fehlende Keys sind 0. Gibt null zurueck, wenn die Quelle
 * fehlt (kein Report / NULL-Spalte) — Aufrufer behandeln das wie bisher.
 */
export function normalizeSeverityCounts(raw: unknown): SeverityCounts | null {
  if (raw == null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const src = raw as Record<string, unknown>;
  const out = emptyCounts();
  for (const [k, v] of Object.entries(src)) {
    const key = k.toUpperCase();
    if ((SEVERITY_KEYS as readonly string[]).includes(key)) {
      out[key as SeverityKey] = toCount(v);
    }
  }
  return out;
}

/**
 * Summe aller Severity-Zaehler (Anzahl gezaehlter Findings).
 * Akzeptiert sowohl die rohe Spalte als auch eine normalisierte Map.
 */
export function sumSeverityCounts(counts: unknown): number {
  if (!counts || typeof counts !== 'object') return 0;
  return Object.values(counts as Record<string, unknown>).reduce<number>(
    (sum, v) => sum + toCount(v),
    0,
  );
}

/**
 * Zaehlt ein findings-Array deterministisch nach Severity — identische
 * Semantik wie der DB-Trigger reports_update_severity_counts (Migration 018):
 * lower-case-Vergleich des `severity`-Feldes, Ergebnis in kanonischer
 * UPPER-case-Form. Dies ist die Grundwahrheit, gegen die AC2 reconcilet.
 */
export function countFindingsBySeverity(findings: unknown): SeverityCounts {
  const out = emptyCounts();
  if (!Array.isArray(findings)) return out;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const sev = String((f as Record<string, unknown>).severity ?? '').toUpperCase();
    if ((SEVERITY_KEYS as readonly string[]).includes(sev)) {
      out[sev as SeverityKey] += 1;
    }
  }
  return out;
}

/**
 * AC2-Invariante fuer die Findings-Detailseite (die einzige Oberflaeche, die
 * sowohl die autoritative Spalte ALS AUCH das gelistete findings-Array hat):
 * Die angezeigten Severity-Zaehler MUESSEN den gelisteten Findings entsprechen.
 *
 * Strategie:
 *   1. Autoritative Spalte normalisieren (Primaerquelle, AC1).
 *   2. Aus dem gelisteten findings-Array frisch nachzaehlen.
 *   3. Stimmen beide ueberein -> autoritative Spalte zurueckgeben (unveraendert).
 *   4. Bei Drift NICHT still die (potentiell falsche) Spalte rendern, sondern
 *      die Zaehlung aus den TATSAECHLICH gelisteten Findings nehmen (reconcile)
 *      und das via onDrift signalisieren (Logging). So kann "Karte zeigt 12,
 *      Liste zeigt 11" strukturell nicht mehr passieren.
 */
export function reconcileSeverityCounts(
  authoritative: unknown,
  findings: unknown,
  onDrift?: (info: { authoritative: SeverityCounts | null; recounted: SeverityCounts }) => void,
): SeverityCounts {
  const recounted = countFindingsBySeverity(findings);
  const auth = normalizeSeverityCounts(authoritative);
  if (auth && SEVERITY_KEYS.every((k) => auth[k] === recounted[k])) {
    return auth;
  }
  if (onDrift) onDrift({ authoritative: auth, recounted });
  return recounted;
}
