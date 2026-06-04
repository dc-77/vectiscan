import {
  normalizeSeverityCounts,
  sumSeverityCounts,
  countFindingsBySeverity,
  reconcileSeverityCounts,
  SEVERITY_KEYS,
} from '../lib/severityCounts';

// ============================================================
// VEC-123: Severity-Zähler-Drift härten
// ============================================================
// Beweist, dass der Order-/Dashboard-Anzeigepfad der AUTORITATIVEN,
// trigger-berechneten Quelle (reports.severity_counts, lower-case) folgt und
// NICHT dem eingebetteten, handpflegbaren findings_data->'severity_counts'
// (UPPER-case), das driften kann.
//
// CI-tauglich: reine Funktions-Unit-Tests, kein externer Stack/DB noetig.
// Die DB-Trigger-Semantik (Migration 018: zaehle findings_data->'findings'
// per lower-case severity) wird durch countFindingsBySeverity gespiegelt.
// ============================================================

// Demo-Drift-Szenario aus VEC-120: 11 tatsaechlich gelistete Findings,
// aber das eingebettete severity_counts behauptet 12.
const LISTED_FINDINGS = [
  { id: 'f1', severity: 'CRITICAL' },
  { id: 'f2', severity: 'CRITICAL' },
  { id: 'f3', severity: 'HIGH' },
  { id: 'f4', severity: 'HIGH' },
  { id: 'f5', severity: 'HIGH' },
  { id: 'f6', severity: 'MEDIUM' },
  { id: 'f7', severity: 'MEDIUM' },
  { id: 'f8', severity: 'MEDIUM' },
  { id: 'f9', severity: 'MEDIUM' },
  { id: 'f10', severity: 'LOW' },
  { id: 'f11', severity: 'LOW' },
]; // → 2C / 3H / 4M / 2L / 0I = 11

// Was der DB-Trigger (Migration 018) aus LISTED_FINDINGS berechnet:
// reports.severity_counts (autoritativ, lower-case keys).
const AUTHORITATIVE_COLUMN = { critical: 2, high: 3, medium: 4, low: 2, info: 0 };

// Was im findings_data eingebettet steht und GEDRIFTET ist (behauptet 12:
// ein HIGH zu viel) — UPPER-case keys wie vom Reporter geschrieben.
const DRIFTED_EMBEDDED = { CRITICAL: 2, HIGH: 4, MEDIUM: 4, LOW: 2, INFO: 0 };

describe('VEC-123 normalizeSeverityCounts', () => {
  it('normalisiert die autoritative lower-case-Spalte in kanonische UPPER-case-Form', () => {
    expect(normalizeSeverityCounts(AUTHORITATIVE_COLUMN)).toEqual({
      CRITICAL: 2,
      HIGH: 3,
      MEDIUM: 4,
      LOW: 2,
      INFO: 0,
    });
  });

  it('fuellt fehlende Severities mit 0 und ignoriert unbekannte Keys', () => {
    expect(normalizeSeverityCounts({ high: 1, bogus: 99 })).toEqual({
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    });
  });

  it('gibt null zurueck, wenn keine Quelle vorhanden ist (kein Report)', () => {
    expect(normalizeSeverityCounts(null)).toBeNull();
    expect(normalizeSeverityCounts(undefined)).toBeNull();
    expect(normalizeSeverityCounts([])).toBeNull();
  });

  it('coerced numerische Strings (JSONB kann Strings liefern)', () => {
    expect(normalizeSeverityCounts({ critical: '5', high: '0' })).toEqual({
      CRITICAL: 5,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    });
  });
});

describe('VEC-123 countFindingsBySeverity (spiegelt DB-Trigger 018)', () => {
  it('zaehlt das gelistete findings-Array deterministisch', () => {
    expect(countFindingsBySeverity(LISTED_FINDINGS)).toEqual({
      CRITICAL: 2,
      HIGH: 3,
      MEDIUM: 4,
      LOW: 2,
      INFO: 0,
    });
  });

  it('vergleicht Severities case-insensitiv (Reporter UPPER, Policy lower)', () => {
    const mixed = [{ severity: 'High' }, { severity: 'high' }, { severity: 'HIGH' }];
    expect(countFindingsBySeverity(mixed).HIGH).toBe(3);
  });

  it('liefert leere Zaehlung fuer Nicht-Arrays', () => {
    expect(countFindingsBySeverity(null)).toEqual({
      CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
    });
  });
});

describe('VEC-123 AC3: Anzeige folgt der autoritativen Quelle, nicht dem Drift', () => {
  it('autoritative Spalte == gelistete Findings (11), Drift behauptet 12', () => {
    const authoritative = normalizeSeverityCounts(AUTHORITATIVE_COLUMN)!;
    const recounted = countFindingsBySeverity(LISTED_FINDINGS);

    // Autoritativ folgt den gelisteten Findings.
    expect(authoritative).toEqual(recounted);
    expect(sumSeverityCounts(authoritative)).toBe(11);
    expect(LISTED_FINDINGS.length).toBe(11);

    // Der Drift behauptet etwas anderes — und darf NICHT die Anzeige sein.
    expect(sumSeverityCounts(DRIFTED_EMBEDDED)).toBe(12);
    expect(authoritative).not.toEqual(DRIFTED_EMBEDDED);
    expect(authoritative.HIGH).toBe(3); // nicht 4 aus dem Drift
  });

  it('reconcile gibt die autoritative Zaehlung zurueck, wenn alles stimmt', () => {
    const onDrift = jest.fn();
    const result = reconcileSeverityCounts(AUTHORITATIVE_COLUMN, LISTED_FINDINGS, onDrift);
    expect(result).toEqual({ CRITICAL: 2, HIGH: 3, MEDIUM: 4, LOW: 2, INFO: 0 });
    expect(onDrift).not.toHaveBeenCalled(); // keine Drift -> stiller Pass
  });

  it('reconcile folgt den gelisteten Findings und meldet Drift, wenn die Spalte luegt', () => {
    const onDrift = jest.fn();
    // Selbst wenn die als autoritativ uebergebene Quelle gedriftet waere (12),
    // gewinnt die Zaehlung aus den TATSAECHLICH gelisteten Findings (11).
    const result = reconcileSeverityCounts(DRIFTED_EMBEDDED, LISTED_FINDINGS, onDrift);
    expect(sumSeverityCounts(result)).toBe(11);
    expect(result.HIGH).toBe(3);
    expect(onDrift).toHaveBeenCalledTimes(1);
  });

  it('AC2-Invariante: Summe der angezeigten Zaehler == Anzahl gelisteter Findings', () => {
    const result = reconcileSeverityCounts(AUTHORITATIVE_COLUMN, LISTED_FINDINGS);
    expect(sumSeverityCounts(result)).toBe(LISTED_FINDINGS.length);
  });
});

describe('VEC-123 AC4: korrekte Reports bleiben unveraendert', () => {
  it('normalizeSeverityCounts ist idempotent fuer bereits korrekte UPPER-case-Counts', () => {
    const correct = { CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 5 };
    expect(normalizeSeverityCounts(correct)).toEqual(correct);
  });

  it('alle kanonischen Keys sind immer praesent', () => {
    const out = normalizeSeverityCounts({ critical: 1 })!;
    for (const k of SEVERITY_KEYS) {
      expect(out).toHaveProperty(k);
      expect(typeof out[k]).toBe('number');
    }
  });
});
