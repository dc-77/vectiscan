/**
 * Integrations-Regressionstest fuer VEC-33 / VEC-102 (Finding C1).
 *
 * Der Stripe-Unit-Test (stripe_webhook.test.ts) baut das Webhook-Plugin
 * ISOLIERT auf einem nackten Fastify() — dabei ist der eingebaute Default-
 * JSON-Parser ueberschreibbar und der Test bleibt gruen. Die REALE
 * Komposition in server.ts registriert aber einen *custom* globalen
 * application/json-Parser. Ein zweiter custom-Parser im encapsulated
 * Webhook-Scope wuerde FST_ERR_CTP_ALREADY_PRESENT werfen und die GESAMTE
 * API am Boot hindern (start() -> process.exit(1)).
 *
 * Dieser Test bootet deshalb den ECHTEN buildServer() und beweist:
 *   1. buildServer().ready() laeuft durch (kein Content-Type-Parser-Konflikt).
 *   2. Die Webhook-Route erhaelt den ROHEN Body als Buffer (Signaturpruefung
 *      intakt) — der globale Parser wird im Plugin-Scope korrekt ersetzt.
 *
 * Gegen den ungefixten Code schlaegt bereits `await buildServer().ready()`
 * fehl; mit dem removeContentTypeParser-Fix ist er gruen.
 */

// Stripe als konfiguriert mocken; constructEvent merkt sich, ob es einen
// Buffer bekommen hat (das ist der eigentliche Beweis fuer den Raw-Body).
let lastConstructArgWasBuffer: boolean | null = null;
jest.mock('../lib/stripe', () => {
  return {
    isStripeConfigured: () => true,
    getWebhookSecret: () => 'whsec_test',
    getStripe: () => ({
      webhooks: {
        constructEvent: (raw: unknown) => {
          lastConstructArgWasBuffer = Buffer.isBuffer(raw);
          return {
            id: 'evt_boot_1',
            type: 'checkout.session.expired',
            data: { object: { id: 'cs_boot', metadata: { subscription_id: 'sub-boot' } } },
          };
        },
      },
    }),
    // Von subscriptions.ts importierte Helfer — fuer den Boot nur als Stubs noetig.
    getPriceIdForPackage: () => 'price_test',
    getCheckoutUrls: () => ({ successUrl: 'https://x/ok', cancelUrl: 'https://x/cancel' }),
  };
});

// Keine echten externen Verbindungen waehrend des Boots/Requests.
jest.mock('../lib/db', () => ({ query: jest.fn().mockResolvedValue({ rowCount: 1, rows: [] }), pool: {}, initDb: jest.fn() }));
jest.mock('../lib/queue', () => ({ enqueuePrecheck: jest.fn().mockResolvedValue(undefined) }));
jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import { buildServer } from '../server';

describe('buildServer() boot + Stripe webhook raw-body (VEC-102 C1)', () => {
  it('boots the full server without a content-type-parser conflict', async () => {
    const app = buildServer();
    // Gegen den ungefixten Code wirft genau diese Zeile
    // "Content type parser 'application/json' already present.".
    await expect(app.ready()).resolves.toBeDefined();
    await app.close();
  });

  it('delivers the raw request body as a Buffer to the webhook route', async () => {
    lastConstructArgWasBuffer = null;
    const app = buildServer();
    await app.ready();

    const res = await app.inject({
      method: 'POST',
      url: '/api/webhooks/stripe',
      headers: { 'content-type': 'application/json', 'stripe-signature': 'sig_ok' },
      payload: '{"raw":"body"}',
    });

    expect(res.statusCode).toBe(200);
    // Der Webhook-Scope muss den globalen JSON-Parser durch den Buffer-Parser
    // ersetzt haben — sonst kaeme hier ein geparstes Objekt an und die
    // Stripe-Signaturpruefung waere kaputt.
    expect(lastConstructArgWasBuffer).toBe(true);
    await app.close();
  });
});
