import { computeTimeToValue } from '../lib/timeToValue';

// ============================================================
// VEC-87 (PA-7) — Onboarding-Time-to-Value-Messpunkt (AC3)
// ============================================================
// Beweist, dass die Spanne Registrierung → erster report_complete
// objektiv berechenbar und auswertbar ist, und dass NUR der erste
// abgeschlossene Report des Kunden gemessen wird (priorCompletedCount).
// Reine Funktions-Unit-Tests, kein DB/Redis-Stack noetig (CI-tauglich).
// ============================================================

describe('computeTimeToValue (VEC-87 AC3)', () => {
  const registeredAt = new Date('2026-06-04T10:00:00.000Z');

  it('misst die Spanne in Sekunden beim ersten Report', () => {
    const completedAt = new Date('2026-06-04T10:18:30.000Z'); // +18:30
    const res = computeTimeToValue({ registeredAt, completedAt, priorCompletedCount: 0 });

    expect(res).not.toBeNull();
    expect(res!.ttvSeconds).toBe(18 * 60 + 30); // 1110
    expect(res!.registeredAt).toBe('2026-06-04T10:00:00.000Z');
    expect(res!.completedAt).toBe('2026-06-04T10:18:30.000Z');
  });

  it('liefert null, wenn der Kunde bereits einen Report abgeschlossen hat', () => {
    const completedAt = new Date('2026-06-04T10:18:30.000Z');
    expect(computeTimeToValue({ registeredAt, completedAt, priorCompletedCount: 1 })).toBeNull();
    expect(computeTimeToValue({ registeredAt, completedAt, priorCompletedCount: 5 })).toBeNull();
  });

  it('rundet Sub-Sekunden korrekt', () => {
    const completedAt = new Date('2026-06-04T10:00:02.600Z'); // +2.6s
    const res = computeTimeToValue({ registeredAt, completedAt, priorCompletedCount: 0 });
    expect(res!.ttvSeconds).toBe(3);
  });

  it('klemmt negative Drift defensiv auf 0 (verwirft die Kennzahl nicht)', () => {
    const completedAt = new Date('2026-06-04T09:59:55.000Z'); // vor Registrierung
    const res = computeTimeToValue({ registeredAt, completedAt, priorCompletedCount: 0 });
    expect(res).not.toBeNull();
    expect(res!.ttvSeconds).toBe(0);
  });

  it('misst auch lange Onboarding-Spannen (mehrere Tage) korrekt', () => {
    const completedAt = new Date('2026-06-06T10:00:00.000Z'); // +2 Tage
    const res = computeTimeToValue({ registeredAt, completedAt, priorCompletedCount: 0 });
    expect(res!.ttvSeconds).toBe(2 * 24 * 60 * 60);
  });
});
