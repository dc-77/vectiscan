/**
 * Invarianz-Regressionstest fuer VEC-133 (Auflage A1 aus dem Security-Review
 * von VEC-131 / AC3-Gate fuer VEC-34).
 *
 * KLASSE: Broken Function-Level Authorization am Edge (OWASP API5).
 *
 * Der Edge-Admin-Shield (Traefik) deckt nach dem Go-live-Cutover (VEC-34) nur
 * Routen unter dem Praefix `/api/admin/*` ab. Jede admin-privilegierte Route
 * (preHandler enthaelt `requireAdmin`), die NICHT unter `/api/admin` liegt,
 * waere nach dem Cutover oeffentlich erreichbar und nur noch durch die In-App-
 * Pruefung geschuetzt — die zweite Schicht (Defense in Depth) fehlte.
 *
 * Dieser Test enumeriert ALLE registrierten Routen ueber den `onRoute`-Hook
 * (vor der Plugin-Registrierung gesetzt) und beweist die Invariante als KLASSE,
 * nicht nur fuer die heute bekannten 4 Instanzen: kein `requireAdmin`-Handler
 * darf ausserhalb von `/api/admin` haengen.
 *
 * Gegen den ungefixten Code (4 Routen unter `/api/orders/*`) ist `offenders`
 * nicht leer und der Test schlaegt fehl; nach der Konsolidierung ist er gruen.
 * Eine kuenftig neu eingefuehrte Admin-Route ausserhalb `/api/admin` laesst ihn
 * sofort wieder rot werden.
 */

// Keine echten externen Verbindungen waehrend des Boots (Muster wie
// server_boot_webhook.test.ts). buildServer() registriert nur die Route-
// Plugins; deren Modul-Importe duerfen keine Sockets oeffnen.
jest.mock('../lib/stripe', () => ({
  isStripeConfigured: () => true,
  getWebhookSecret: () => 'whsec_test',
  getStripe: () => ({ webhooks: { constructEvent: () => ({}) } }),
  getPriceIdForPackage: () => 'price_test',
  getCheckoutUrls: () => ({ successUrl: 'https://x/ok', cancelUrl: 'https://x/cancel' }),
}));
jest.mock('../lib/db', () => ({ query: jest.fn().mockResolvedValue({ rowCount: 0, rows: [] }), pool: {}, initDb: jest.fn() }));
jest.mock('../lib/queue', () => ({ enqueuePrecheck: jest.fn().mockResolvedValue(undefined), publishEvent: jest.fn(), reportQueue: { add: jest.fn() }, scanQueue: { add: jest.fn() } }));
jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import { buildServer } from '../server';

describe('Edge-Shield-Invariante (VEC-133 / A1)', () => {
  it('jede requireAdmin-Route liegt unter /api/admin (Edge-Admin-Shield-Deckung)', async () => {
    const app = buildServer();

    const offenders: string[] = [];
    // onRoute muss VOR der Routen-Registrierung greifen. buildServer() queued
    // die register()-Aufrufe; sie laufen erst in ready(). Der hier am Root
    // gesetzte Hook wird von allen danach registrierten (Kind-)Scopes geerbt.
    app.addHook('onRoute', (route) => {
      const preHandlers = ([] as unknown[]).concat(route.preHandler ?? []);
      const isAdminGuarded = preHandlers.some(
        (h) => typeof h === 'function' && (h as { name?: string }).name === 'requireAdmin',
      );
      if (isAdminGuarded && !route.url.startsWith('/api/admin')) {
        offenders.push(`${route.method} ${route.url}`);
      }
    });

    await app.ready();
    await app.close();

    expect(offenders).toEqual([]);
  });
});
