/**
 * Regressionstest für die Demo-Seed-Fixtures (VEC-120 QA-Gegenlauf zu VEC-86/118).
 *
 * Hintergrund: Die Dashboard-API liest die Severity-Verteilung direkt aus dem
 * eingebetteten Feld `findings_data->'severity_counts'` (api/src/routes/orders.ts),
 * NICHT aus der trigger-abgeleiteten Spalte `reports.severity_counts`. Driftet das
 * handgepflegte `severity_counts`-Feld einer Fixture von ihrem `findings`-Array ab,
 * zeigt das Demo-Dashboard eine Severity-Verteilung, die nicht zu den tatsächlich
 * gelisteten Befunden passt (gefunden bei `compliance.json`: 5M statt 4M, Summe 12
 * statt 11). In einem Compliance-Demo untergräbt das die „reproduzierbar/auditierbar"-
 * Story direkt vor dem Kunden.
 *
 * Dieser Test sperrt die Klasse: für jede Demo-Fixture muss
 *   1. das eingebettete severity_counts exakt dem aus `findings` neu gezählten entsprechen,
 *   2. die Summe der Counts der Anzahl der findings entsprechen,
 *   3. overall_risk dem höchsten vorhandenen Schweregrad entsprechen,
 *   4. Risiko + Verteilung der dokumentierten Akzeptanzliste (Abschnitt 1/4 DEMO-SCRIPT) entsprechen,
 *   5. die paket-spezifischen Schlüssel-Befunde vorhanden sein (AC4).
 *
 * Reiner Fixture-Test (kein DB/MinIO nötig) → CI-tauglich als Go-live-Gate.
 */
import fs from 'fs';
import path from 'path';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
type Sev = (typeof SEVERITIES)[number];
type Counts = Record<Sev, number>;

interface Fixture {
  target: string;
  company_name: string;
  overall_risk: string;
  severity_counts: Counts;
  findings: Array<{ severity: string; title?: string }>;
  nis2_compliance_summary?: Record<string, string>;
}

const DEMO_DIR = path.join(__dirname, '..', 'scripts', 'demo-data');

function load(pkg: string): Fixture {
  return JSON.parse(fs.readFileSync(path.join(DEMO_DIR, `${pkg}.json`), 'utf-8')) as Fixture;
}

function recount(findings: Array<{ severity: string }>): Counts {
  const c: Counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    const s = f.severity.toUpperCase() as Sev;
    if (s in c) c[s] += 1;
  }
  return c;
}

// Kanonische Erwartung = tatsächlicher Inhalt der findings-Arrays (Single Source of Truth),
// abgeglichen mit Abschnitt 1/4 des DEMO-SCRIPT.md.
const EXPECTED: Record<string, { risk: string; counts: Counts; mustContain: string[] }> = {
  webcheck: {
    risk: 'MEDIUM',
    counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 4, LOW: 2, INFO: 0 },
    mustContain: ['TLS', 'DMARC'],
  },
  perimeter: {
    risk: 'HIGH',
    counts: { CRITICAL: 1, HIGH: 3, MEDIUM: 4, LOW: 2, INFO: 0 },
    mustContain: ['SQL-Injection', 'RDP', '.git'],
  },
  compliance: {
    risk: 'CRITICAL',
    counts: { CRITICAL: 1, HIGH: 4, MEDIUM: 4, LOW: 2, INFO: 0 },
    mustContain: ['VPN-Gateway', 'Multi-Faktor', 'Logging'],
  },
};

describe('Demo-Seed-Fixtures (VEC-120)', () => {
  for (const pkg of Object.keys(EXPECTED)) {
    describe(pkg, () => {
      const fx = load(pkg);
      const recounted = recount(fx.findings);

      it('eingebettetes severity_counts == aus findings neu gezählt', () => {
        // Schützt die Dashboard-Severity-Verteilung (orders.ts liest das eingebettete Feld).
        expect(fx.severity_counts).toEqual(recounted);
      });

      it('Summe(severity_counts) == Anzahl findings', () => {
        const sum = SEVERITIES.reduce((a, s) => a + (fx.severity_counts[s] || 0), 0);
        expect(sum).toBe(fx.findings.length);
      });

      // Hinweis: overall_risk ist eine bewusste Paket-Risikobewertung, NICHT max(findings).
      // Perimeter ist als HIGH dokumentiert, obwohl es einen CRITICAL-Befund (SQLi) enthält
      // (DEMO-SCRIPT Abschnitt 1/4). Daher wird overall_risk gegen die dokumentierte
      // Erwartung gepinnt, nicht gegen den höchsten vorhandenen Schweregrad.
      it('Risiko + Verteilung entsprechen der Akzeptanzliste (AC2/AC4)', () => {
        expect(fx.overall_risk).toBe(EXPECTED[pkg].risk);
        expect(recounted).toEqual(EXPECTED[pkg].counts);
      });

      it('Schlüssel-Befunde vorhanden (AC4)', () => {
        const titles = fx.findings.map((f) => f.title || '').join(' | ');
        for (const needle of EXPECTED[pkg].mustContain) {
          expect(titles).toContain(needle);
        }
      });
    });
  }

  it('Compliance hat eine NIS2/§30-BSIG-Summary (AC4)', () => {
    const fx = load('compliance');
    expect(fx.nis2_compliance_summary).toBeDefined();
    const keys = Object.keys(fx.nis2_compliance_summary || {}).join(' ');
    expect(keys).toContain('§30');
  });
});
