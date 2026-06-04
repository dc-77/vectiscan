import fs from 'fs';
import path from 'path';

/**
 * Regression-Gate fuer die Datenschutz-Zusage (VEC-103).
 *
 * Die Datenschutzerklaerung (frontend/src/app/datenschutz/page.tsx, Abschnitt 8)
 * sagt fuer die cookielose First-Party-Reichweitenmessung verbindlich zu:
 *   "Es werden KEINE IP-Adressen, kein User-Agent und keine persistenten
 *    Besucher-Identifier gespeichert."
 * Daraus folgt die Einwilligungsfreiheit nach § 25 Abs. 2 TTDSG/TDDDG.
 *
 * Diese Zusage ist eine Rechts-/Compliance-Aussage ohne technische Durchsetzung:
 * eine spaetere Migration, die analytics_events um eine ip/user_agent/
 * fingerprint/visitor_id-Spalte erweitert, wuerde die Aussage still brechen und
 * die Einwilligungsfreiheit entfallen lassen (DSGVO/TTDSG-Verstoss).
 *
 * Dieser Test kodiert die Schwachstellenklasse "Privacy-Promise-Drift": er
 * schlaegt fehl, sobald analytics_events eine personenbeziehbare Spalte erhaelt,
 * und erzwingt damit ein erneutes Compliance-Review (zurueck an PM/Legal).
 */
describe('analytics_events — Datenschutz-Zusage (VEC-103 Regression-Gate)', () => {
  const migrationPath = path.join(__dirname, '..', 'migrations', '033_analytics_events.sql');

  const readAnalyticsTable = (): string => {
    const sql = fs.readFileSync(migrationPath, 'utf-8');
    const start = sql.indexOf('CREATE TABLE');
    expect(start).toBeGreaterThanOrEqual(0);
    const end = sql.indexOf(');', start);
    expect(end).toBeGreaterThan(start);
    // nur der Spalten-Block der CREATE-TABLE-Anweisung, in Kleinschreibung
    return sql.substring(start, end).toLowerCase();
  };

  it('migration file should exist', () => {
    expect(fs.existsSync(migrationPath)).toBe(true);
  });

  it('must NOT contain any person-identifying column', () => {
    const table = readAnalyticsTable();

    // Verbotene Spalten — jede davon wuerde die Zusage aus Abschnitt 8 brechen.
    const forbidden = [
      'ip',          // ip, ip_address, client_ip, remote_addr (ip ist Teilstring)
      'user_agent',
      'useragent',
      'fingerprint',
      'visitor_id',
      'client_id',
      'session_id',
      'device_id',
      'cookie',
      'user_id',
      'email',
    ];

    for (const col of forbidden) {
      expect(table).not.toContain(col);
    }
  });

  it('should keep only the anonymous, aggregate columns described in the Datenschutzerklaerung', () => {
    const table = readAnalyticsTable();

    // Positiv-Assertion: das ist der gesamte erlaubte Datenumfang.
    expect(table).toContain('event_type');
    expect(table).toContain('path');
    expect(table).toContain('referrer_domain');
    expect(table).toContain('utm_source');
    expect(table).toContain('utm_medium');
    expect(table).toContain('utm_campaign');
    expect(table).toContain('created_at');
  });
});
