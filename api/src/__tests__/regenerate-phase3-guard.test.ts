/**
 * BEFUND 4 — Der Report-Regenerate-Pfad darf ein LEERES phase3-Objekt ("{}")
 * nicht wie vorhandene Korrelationsdaten behandeln.
 *
 * Eine phase3_correlation-skip-Zeile traegt raw_output="{}"; JSON.parse("{}")
 * liefert ein truthy, aber leeres Objekt. Ohne Keys-Check wuerde der jobPayload
 * enrichment={}/correlatedFindings=[]/businessImpactScore=0/phase3Summary={}
 * setzen statt die Felder ungesetzt zu lassen. Der Guard muss auf
 * Object.keys(...).length > 0 pruefen.
 */
import { readFileSync } from 'fs';
import { join } from 'path';

const ordersSrc = readFileSync(join(__dirname, '..', 'routes', 'orders.ts'), 'utf8');

describe('Report-Regenerate: leeres phase3-Objekt', () => {
  it('prueft phase3Data zusaetzlich auf nicht-leere Keys', () => {
    expect(ordersSrc).toMatch(
      /if\s*\(phase3Data\s*&&\s*Object\.keys\(phase3Data\)\.length\s*>\s*0\)/,
    );
  });

  it('setzt enrichment/correlatedFindings/... erst nach dem Guard', () => {
    const guardIdx = ordersSrc.search(
      /if\s*\(phase3Data\s*&&\s*Object\.keys\(phase3Data\)\.length\s*>\s*0\)/,
    );
    expect(guardIdx).toBeGreaterThan(-1);
    // Alle vier Zuweisungen existieren und liegen hinter dem Guard.
    for (const assign of [
      'jobPayload.enrichment = phase3Data.enrichment',
      'jobPayload.correlatedFindings = phase3Data.correlated_findings',
      'jobPayload.businessImpactScore = phase3Data.business_impact_score',
      'jobPayload.phase3Summary = phase3Data.phase3_summary',
    ]) {
      const idx = ordersSrc.indexOf(assign);
      expect(idx).toBeGreaterThan(guardIdx);
    }
  });
});
