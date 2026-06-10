// ============================================================
// VEC-372 D2: Severity-Verteilung deterministisch & drift-frei (Frontend)
// ============================================================
// Frontend-Pendant zu api/src/lib/severityCounts.ts (getrennte Docker-Build-
// Kontexte → bewusst dupliziert, identische Semantik wie der DB-Trigger
// reports_update_severity_counts, Migration 016/018).
//
// Hintergrund (VEC-372 D2): Das eingebettete reports.findings_data->'severity_counts'
// kann vom tatsächlich gelisteten findings-Array DRIFTEN. Im Produktiv-Report
// f07b091b labelte es alle 7 Befunde fälschlich als "Info" (statt 1H/3M/2L/1I) —
// das untertreibt das Risiko massiv. Die autoritative Quelle ist die Trigger-
// berechnete Spalte reports.severity_counts (hier als audit_severity_counts
// durchgereicht, lower-case keys). Diese Helfer normalisieren sie in die
// kanonische UPPER-case-Form, die Frontend-Komponenten erwarten, und gleichen
// sie gegen das gelistete findings-Array ab.
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
 * Normalisiert eine rohe severity_counts-Map (beliebige Groß-/Kleinschreibung)
 * in die kanonische UPPER-case-Form. Unbekannte Severities werden ignoriert,
 * fehlende Keys sind 0. Gibt null zurück, wenn die Quelle fehlt.
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
 * Zählt ein findings-Array deterministisch nach Severity — identische Semantik
 * wie der DB-Trigger (lower-case-Vergleich des `severity`-Feldes, Ergebnis in
 * kanonischer UPPER-case-Form). Dies ist die Grundwahrheit, gegen die D2 reconcilet.
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
 * VEC-372 D2: Die anzuzeigende Severity-Verteilung MUSS den gelisteten Findings
 * entsprechen. Strategie:
 *   1. Autoritative Spalte (audit_severity_counts) normalisieren.
 *   2. Aus dem gelisteten findings-Array frisch nachzählen.
 *   3. Stimmen beide überein → autoritative Spalte zurückgeben.
 *   4. Bei Drift NICHT still die (potentiell falsche) Spalte rendern, sondern die
 *      Nachzählung aus den TATSÄCHLICH gelisteten Findings nehmen. So kann
 *      "Badge zeigt 7 Info, Liste zeigt 1H/3M/2L/1I" strukturell nicht mehr passieren.
 */
export function reconcileSeverityCounts(
  authoritative: unknown,
  findings: unknown,
): SeverityCounts {
  const recounted = countFindingsBySeverity(findings);
  const auth = normalizeSeverityCounts(authoritative);
  if (auth && SEVERITY_KEYS.every((k) => auth[k] === recounted[k])) {
    return auth;
  }
  return recounted;
}
