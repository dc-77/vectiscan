/**
 * VEC-289 — Katalog-Parity & Drift-Guard.
 *
 * Erzwingt, dass `catalog/packages.catalog.json` die EINZIGE Wahrheit ist:
 *  1. Beide generierten Module (api + frontend) sind aktuell (kein Drift).
 *  2. Der Katalog hat genau die 5 CEO-freigegebenen Pakete.
 *  3. Backend-Validierung (PACKAGE_KEYS) == Katalog.
 *  4. DB-CHECK-Constraints (subscriptions/orders/scan_schedules) == Katalog.
 */
import * as fs from 'fs';
import * as path from 'path';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const gen = require('../../../scripts/gen-catalog.js');
import { PACKAGE_KEYS } from '../lib/catalog.generated.js';

const EXPECTED_KEYS = ['webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance'];

/** Extrahiert die Paket-Keys aus `... package IN ('a','b',...)` einer SQL-Datei. */
function packageKeysFromConstraint(sqlFile: string): string[][] {
  const sql = fs.readFileSync(path.join(gen.ROOT, 'api', 'src', 'migrations', sqlFile), 'utf8');
  const out: string[][] = [];
  const re = /package\s+IN\s*\(([^)]*)\)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(sql)) !== null) {
    const keys = m[1]
      .split(',')
      .map((s) => s.trim().replace(/^'|'$/g, ''))
      .filter(Boolean);
    out.push(keys.sort());
  }
  return out;
}

describe('VEC-289 Paket-Katalog — single source of truth', () => {
  it('hat genau die 5 kanonischen Pakete in Katalog-Reihenfolge', () => {
    expect([...PACKAGE_KEYS]).toEqual(EXPECTED_KEYS);
  });

  it('generierte Module (api + frontend) sind aktuell — kein Drift zur SSoT', () => {
    const expected = gen.renderCatalogModule(gen.loadCatalog());
    for (const target of gen.TARGETS as string[]) {
      expect(fs.existsSync(target)).toBe(true);
      const actual = fs.readFileSync(target, 'utf8');
      expect(actual).toBe(expected);
    }
  });

  it('subscriptions-CHECK-Constraint deckt sich mit dem Katalog (5)', () => {
    const constraints = packageKeysFromConstraint('012_subscriptions_review_workflow.sql');
    expect(constraints.length).toBeGreaterThan(0);
    for (const keys of constraints) {
      expect(keys).toEqual([...EXPECTED_KEYS].sort());
    }
  });

  it('orders- und scan_schedules-CHECK-Constraints decken sich mit dem Katalog (5)', () => {
    const constraints = packageKeysFromConstraint('009_v2_packages.sql');
    // Migration 009 enthaelt die Daten-Migration UND die neuen 5er-Constraints.
    const fiveKeySets = constraints.filter((k) => k.length === EXPECTED_KEYS.length);
    expect(fiveKeySets.length).toBeGreaterThanOrEqual(2); // orders + scan_schedules
    for (const keys of fiveKeySets) {
      expect(keys).toEqual([...EXPECTED_KEYS].sort());
    }
  });
});
