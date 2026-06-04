import Fastify, { FastifyInstance } from 'fastify';
import rateLimit from '@fastify/rate-limit';

/**
 * VEC-110 — Rate-Limiting/Abuse-Schutz für die öffentlichen, unauthentifizierten
 * Endpunkte (OWASP API4:2023 — Unrestricted Resource Consumption).
 *
 * Beweist:
 *  - POST /api/leads ist auf 5/min/IP gedrosselt; die 6. Anfrage -> 429.
 *  - POST /api/analytics/collect ist auf 60/min/IP gedrosselt; die 61. -> 429.
 *  - Honeypot: ein gesetztes verstecktes `website`-Feld wird verworfen
 *    (kein DB-Insert, keine Vertriebs-E-Mail), ohne dem Bot ein Signal zu geben.
 *
 * Spiegelt die Plugin-Registrierung aus server.ts (global: false +
 * errorResponseBuilder), damit der Test die produktive Drosselung prüft.
 */

jest.mock('../lib/db', () => ({
  query: jest.fn(),
  initDb: jest.fn(),
  pool: { end: jest.fn() },
}));

jest.mock('../lib/email', () => ({
  sendDemoLeadEmail: jest.fn(),
}));

import { query } from '../lib/db';
import { sendDemoLeadEmail } from '../lib/email';
import { leadRoutes } from '../routes/leads';
import { analyticsRoutes } from '../routes/analytics';

const mockQuery = query as jest.MockedFunction<typeof query>;
const mockSend = sendDemoLeadEmail as jest.MockedFunction<typeof sendDemoLeadEmail>;

async function build(): Promise<FastifyInstance> {
  const server = Fastify();
  await server.register(rateLimit, {
    global: false,
    errorResponseBuilder: (_request, context) => ({
      statusCode: context.statusCode,
      success: false,
      error: 'rate_limited',
      retryAfter: Math.ceil(Number(context.ttl) / 1000),
    }),
  });
  await server.register(leadRoutes);
  await server.register(analyticsRoutes);
  await server.ready();
  return server;
}

const validLead = {
  email: 'erika@mustermann-gmbh.de',
  consent: true,
};

describe('VEC-110 — Rate-Limiting öffentlicher Endpunkte', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    // Lead-Persistenz + Routing dürfen unbegrenzt "gelingen", damit der Test
    // ausschließlich das Limit prüft (nicht Validierung/DB-Fehler).
    mockQuery.mockResolvedValue({ rows: [{ id: 'lead-x' }] } as never);
    mockSend.mockResolvedValue(true);
    server = await build();
  });
  afterEach(async () => {
    await server.close();
  });

  it('POST /api/leads: erlaubt 5/min, drosselt die 6. Anfrage mit 429', async () => {
    for (let i = 0; i < 5; i++) {
      const ok = await server.inject({ method: 'POST', url: '/api/leads', payload: validLead });
      expect(ok.statusCode).toBe(200);
    }

    const blocked = await server.inject({ method: 'POST', url: '/api/leads', payload: validLead });
    expect(blocked.statusCode).toBe(429);
    const body = blocked.json();
    expect(body.success).toBe(false);
    expect(body.error).toBe('rate_limited');
  });

  it('POST /api/analytics/collect: erlaubt 60/min, drosselt die 61. mit 429', async () => {
    const pageview = { path: '/pricing' };
    for (let i = 0; i < 60; i++) {
      const ok = await server.inject({ method: 'POST', url: '/api/analytics/collect', payload: pageview });
      expect(ok.statusCode).toBe(204);
    }

    const blocked = await server.inject({ method: 'POST', url: '/api/analytics/collect', payload: pageview });
    expect(blocked.statusCode).toBe(429);
    expect(blocked.json().error).toBe('rate_limited');
  });

  it('die beiden Limits sind unabhängig (eigener Bucket pro Route)', async () => {
    // Leads-Limit ausschöpfen ...
    for (let i = 0; i < 6; i++) {
      await server.inject({ method: 'POST', url: '/api/leads', payload: validLead });
    }
    // ... darf Analytics nicht beeinflussen.
    const analytics = await server.inject({
      method: 'POST',
      url: '/api/analytics/collect',
      payload: { path: '/' },
    });
    expect(analytics.statusCode).toBe(204);
  });

  it('Honeypot: gesetztes website-Feld wird verworfen (kein Insert, keine E-Mail)', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/leads',
      payload: { ...validLead, website: 'http://spam.example' },
    });

    // Bot bekommt eine unverdächtige Erfolgsantwort ...
    expect(res.statusCode).toBe(200);
    expect(res.json().success).toBe(true);
    // ... aber nichts wird persistiert und keine E-Mail verschickt.
    expect(mockQuery).not.toHaveBeenCalled();
    expect(mockSend).not.toHaveBeenCalled();
  });
});
