import {
  reconcileSeverityCounts,
  normalizeSeverityCounts,
  countFindingsBySeverity,
} from '../lib/severityCounts';

/**
 * VEC-372 D2 Regressionstest: Der Produktiv-Report f07b091b zeigte "7 Info",
 * obwohl die Findings 1 High · 3 Medium · 2 Low · 1 Info waren. Ursache: die
 * Severity-Badge las das eingebettete severity_counts (das von den gelisteten
 * Findings driftete) statt aus den Findings nachzuzählen.
 */
describe('VEC-372 D2: Severity-Reconcile', () => {
  const findings = [
    { id: 'F1', severity: 'HIGH' },
    { id: 'F2', severity: 'MEDIUM' },
    { id: 'F3', severity: 'MEDIUM' },
    { id: 'F4', severity: 'MEDIUM' },
    { id: 'F5', severity: 'LOW' },
    { id: 'F6', severity: 'LOW' },
    { id: 'F7', severity: 'INFO' },
  ];

  it('zählt die echte Verteilung aus den Findings (1H/3M/2L/1I)', () => {
    expect(countFindingsBySeverity(findings)).toEqual({
      CRITICAL: 0, HIGH: 1, MEDIUM: 3, LOW: 2, INFO: 1,
    });
  });

  it('ignoriert das driftende "7 Info"-Aggregat und nimmt die Findings-Wahrheit', () => {
    // Embedded/falsches Aggregat wie im Produktiv-Report
    const driftedEmbedded = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 7 };
    const result = reconcileSeverityCounts(driftedEmbedded, findings);
    expect(result).toEqual({ CRITICAL: 0, HIGH: 1, MEDIUM: 3, LOW: 2, INFO: 1 });
    expect(result.INFO).not.toBe(7);
  });

  it('nutzt die autoritative Spalte, wenn sie zu den Findings passt (lower-case keys)', () => {
    const authLower = { critical: 0, high: 1, medium: 3, low: 2, info: 1 };
    expect(reconcileSeverityCounts(authLower, findings)).toEqual({
      CRITICAL: 0, HIGH: 1, MEDIUM: 3, LOW: 2, INFO: 1,
    });
  });

  it('normalizeSeverityCounts liefert null bei fehlender Quelle', () => {
    expect(normalizeSeverityCounts(null)).toBeNull();
    expect(normalizeSeverityCounts(undefined)).toBeNull();
  });

  it('fällt bei null-Spalte auf die Findings-Nachzählung zurück (kein "7 Info")', () => {
    expect(reconcileSeverityCounts(null, findings)).toEqual({
      CRITICAL: 0, HIGH: 1, MEDIUM: 3, LOW: 2, INFO: 1,
    });
  });
});
