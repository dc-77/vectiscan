/**
 * S6 — kein Bericht ohne Admin-Freigabe.
 *
 * Gefunden beim Umschalten auf v3: `POST /api/orders/:id/regenerate-report` trug
 * nur `requireAuth` und schickte vorhandene finding_exclusions als
 * `excludedFindings` mit, ohne `approved` zu setzen. Der Report-Worker wertete
 * eine nicht leere Ausschlussliste aber als Freigabe und setzte
 * `report_complete`; dieser Status loest in lib/ws-manager.ts ungebremst die
 * Fertig-Mail mit Download-Verweis aus und schreibt die Order auf `delivered`.
 * Ein Kunde konnte seinen Bericht damit an sich selbst ausliefern.
 *
 * Statisch geprueft wie die Nachbartests: die Route braucht die halbe
 * orders.ts-Mockkette, und was hier zaehlt, sind die beiden Stellen.
 */
import { readFileSync } from 'fs';
import { join } from 'path';

const ORDERS = readFileSync(join(__dirname, '..', 'routes', 'orders.ts'), 'utf-8');

describe('S6 — Auslieferung nur nach Admin-Freigabe', () => {
  it('regenerate-report verlangt Admin-Rechte', () => {
    const start = ORDERS.indexOf("'/api/orders/:id/regenerate-report'");
    expect(start).toBeGreaterThan(-1);
    const preHandler = ORDERS.slice(start, start + 200);
    expect(preHandler).toContain('requireAuth, requireAdmin');
  });

  it('nur der Admin-Approve-Weg setzt approved', () => {
    // `approved: true` darf ausschliesslich im Admin-Endpunkt stehen. Kaeme es
    // an einer zweiten Stelle dazu, waere der Worker wieder umgehbar.
    const treffer = ORDERS.match(/approved:\s*true/g) ?? [];
    expect(treffer).toHaveLength(1);
    const stelle = ORDERS.indexOf('approved: true');
    const davor = ORDERS.slice(0, stelle);
    const letzteRoute = davor.lastIndexOf("'/api/admin/orders/:id/approve'");
    expect(letzteRoute).toBeGreaterThan(-1);
  });

  it('regenerate-report setzt approved nicht', () => {
    const start = ORDERS.indexOf("'/api/orders/:id/regenerate-report'");
    const ende = ORDERS.indexOf('server.', start + 10);
    const route = ORDERS.slice(start, ende > start ? ende : start + 4000);
    expect(route).not.toContain('approved: true');
  });
});
