/**
 * Regressionstest VEC-153 (Sven/Security) — Demo-Seed darf das Passwort NICHT loggen.
 *
 * Schwachstellenklasse: Insertion of Sensitive Information into Log File (CWE-532).
 * Vor VEC-153 echote `seed-demo.ts` `Passwort: ${DEMO_PASSWORD || 'VectiScanDemo2026!'}`
 * im Klartext ins Job-Log. Beim host-Secret-Fallback (unmaskiert) landete das
 * (langlebige) Demo-Passwort damit im internen CI-Trace.
 *
 * Dieser Test sperrt die Klasse statisch (kein DB/MinIO nötig → CI-tauglich):
 * keine `console.*`-Zeile im Seed-Skript darf den Passwort-Wert ausgeben — weder
 * die env-Variable DEMO_PASSWORD interpolieren noch das hartkodierte Default-
 * Literal in eine Log-Zeile schreiben.
 *
 * Fällt gegen den alten Code fehl (Zeile ~225), besteht gegen den neuen.
 */
import fs from 'fs';
import path from 'path';

const SEED_SRC = path.join(__dirname, '..', 'scripts', 'seed-demo.ts');
const HARDCODED_DEFAULT = 'VectiScanDemo2026!';

function logLines(src: string): string[] {
  return src.split('\n').filter((l) => /console\.(log|info|warn|error|debug)/.test(l));
}

describe('Demo-Seed Passwort-Echo (VEC-153, CWE-532)', () => {
  const src = fs.readFileSync(SEED_SRC, 'utf-8');
  const logs = logLines(src);

  it('keine console.*-Zeile interpoliert den DEMO_PASSWORD-Wert', () => {
    // Trifft `${...DEMO_PASSWORD...}` / `${...password...}` (Wert-Interpolation),
    // NICHT den bloßen Variablennamen in einem statischen Klartext-Hinweis.
    const offenders = logs.filter((l) => /\$\{[^}]*(DEMO_PASSWORD|password)/i.test(l));
    expect(offenders).toEqual([]);
  });

  it('keine console.*-Zeile gibt das hartkodierte Default-Passwort aus', () => {
    const offenders = logs.filter((l) => l.includes(HARDCODED_DEFAULT));
    expect(offenders).toEqual([]);
  });

  it('es existiert weiterhin ein redigierter Passwort-Hinweis', () => {
    // Stellt sicher, dass die Zeile nicht still verschwunden ist, sondern bewusst
    // auf die Secret-Quelle verweist (Bedienbarkeit für den Operator bleibt).
    expect(/Passwort:\s*\[redigiert\]/.test(src)).toBe(true);
  });
});

describe('Demo-Seed verweigert Quell-Default (VEC-258/VEC-260)', () => {
  const src = fs.readFileSync(SEED_SRC, 'utf-8');

  it('kein stiller `|| Default`-Fallback mehr bei der Passwort-Aufloesung', () => {
    // Die VEC-260-Regression entstand, weil der Seed bei leerem/Default-Wert
    // still das oeffentlich dokumentierte Default seedete. Der OR-Fallback
    // (`process.env.DEMO_PASSWORD || '<default>'`) darf nicht mehr existieren.
    const orFallback = new RegExp(
      'process\\.env\\.DEMO_PASSWORD\\s*\\|\\|\\s*[\'"]' + HARDCODED_DEFAULT,
    );
    expect(orFallback.test(src)).toBe(false);
  });

  it('lehnt den dokumentierten Quell-Default explizit ab (Guardrail vorhanden)', () => {
    // resolveDemoPassword() muss den bekannten Default gegen einen Opt-in
    // pruefen und sonst hart abbrechen.
    expect(src.includes('WELL_KNOWN_DEFAULT')).toBe(true);
    expect(src.includes('DEMO_ALLOW_WELL_KNOWN_PASSWORD')).toBe(true);
    expect(/process\.exit\(1\)/.test(src)).toBe(true);
  });
});
