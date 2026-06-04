import fs from 'fs';
import path from 'path';

/**
 * Regression-Gate fuer die Lead-/Demo-Daten-Transparenz (VEC-109 / VEC-108).
 *
 * Schwachstellenklasse "Privacy-Promise-Drift": Das Demo-Formular
 * (frontend/src/components/DemoRequestForm.tsx) holt eine Einwilligung ein und
 * verweist fuer Details auf die Datenschutzerklaerung. Die eingehenden Lead-Daten
 * (Name, E-Mail, Unternehmen, Telefon, Domain, Nachricht) werden zur internen
 * Weiterleitung an den Vertrieb per E-Mail ueber Resend, Inc. (USA) geroutet
 * (api/src/lib/email.ts::sendDemoLeadEmail).
 *
 * Damit der oeffentliche Compliance-Claim belegbar bleibt, MUSS die
 * Datenschutzerklaerung (frontend/src/app/datenschutz/page.tsx) verbindlich
 * offenlegen:
 *   1. dass Kontakt-/Lead-Daten verarbeitet werden (Art. 6 Abs. 1 lit. a DSGVO,
 *      Einwilligung),
 *   2. dass diese Daten zum Vertriebs-Routing an Resend (USA, SCCs Art. 46)
 *      uebermittelt werden,
 *   3. die Zusage "kein Weiterverkauf".
 *
 * Faellt eine dieser Offenlegungen weg (oder wird Resend als Lead-Empfaenger
 * entfernt, ohne das Routing umzubauen), schlaegt dieser Test fehl und erzwingt
 * ein erneutes Compliance-Review (zurueck an Security/QA + PM/Legal).
 *
 * Spiegelt das Vorbild aus analytics_privacy.test.ts (VEC-103).
 */
describe('Datenschutzerklaerung — Lead-/Demo-Daten-Offenlegung (VEC-109 Regression-Gate)', () => {
  const repoRoot = path.join(__dirname, '..', '..', '..');
  const datenschutzPath = path.join(
    repoRoot,
    'frontend',
    'src',
    'app',
    'datenschutz',
    'page.tsx',
  );
  const emailLibPath = path.join(__dirname, '..', 'lib', 'email.ts');
  const demoFormPath = path.join(
    repoRoot,
    'frontend',
    'src',
    'components',
    'DemoRequestForm.tsx',
  );

  const readDatenschutz = (): string => {
    expect(fs.existsSync(datenschutzPath)).toBe(true);
    return fs.readFileSync(datenschutzPath, 'utf-8');
  };

  it('source files should exist', () => {
    expect(fs.existsSync(datenschutzPath)).toBe(true);
    expect(fs.existsSync(emailLibPath)).toBe(true);
    expect(fs.existsSync(demoFormPath)).toBe(true);
  });

  it('must disclose that contact/lead data is processed', () => {
    const text = readDatenschutz();
    // Lead-Datenkategorie muss benannt sein ...
    expect(text).toContain('Kontakt-/Lead-Daten');
    // ... und die einzelnen Felder, die das Demo-Formular erhebt.
    for (const field of ['Name', 'E-Mail', 'Unternehmen', 'Telefon', 'Domain', 'Nachricht']) {
      expect(text).toContain(field);
    }
  });

  it('must name the legal basis (Einwilligung, Art. 6 Abs. 1 lit. a DSGVO)', () => {
    const text = readDatenschutz();
    expect(text).toContain('Art. 6 Abs. 1 lit. a DSGVO');
    expect(text).toContain('Einwilligung');
  });

  it('must disclose Resend (USA) as recipient for lead/demo routing with SCCs', () => {
    const text = readDatenschutz();
    expect(text).toContain('Resend');
    // Drittland-Uebermittlung + Standardvertragsklauseln muessen genannt sein.
    expect(text).toContain('Art. 46 Abs. 2 lit. c DSGVO');
    // Der Bezug zu Demo-/Lead-Anfragen muss vorhanden sein (nicht nur Passwort/Report).
    expect(text).toMatch(/Demo|Lead|Anfrage/);
  });

  it('must mirror the binding "kein Weiterverkauf" promise', () => {
    const text = readDatenschutz();
    expect(text).toContain('Kein Weiterverkauf');
  });

  it('demo form must not make the unprovable absolute claim "in Deutschland verarbeitet"', () => {
    const form = fs.readFileSync(demoFormPath, 'utf-8');
    // Die absolute Aussage ist unzutreffend, weil das Routing ueber die USA laeuft.
    // Hosting/Speicherung in DE ist belegbar — die Verarbeitung als absolute
    // DE-Aussage nicht. Dieser Guard verhindert die Rueckkehr des falschen Claims.
    expect(form).not.toContain('in Deutschland verarbeitet');
  });
});
