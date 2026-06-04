import Fastify, { FastifyInstance } from 'fastify';

/**
 * VEC-36 — Tracking & Lead-Capture.
 *
 * Beweist die Akzeptanzkriterien auf Route-Ebene (DB + E-Mail gemockt):
 *  - "Testlead kommt im Routing-Ziel an": POST /api/leads persistiert den Lead
 *    UND ruft das Vertriebs-Routing (sendDemoLeadEmail) auf. Faellt das Routing
 *    aus, bleibt der Lead gespeichert (routing_status='failed') — kein Verlust.
 *  - "Analytics erfasst Traffic": POST /api/analytics/collect schreibt einen
 *    Pageview OHNE personenbezogene Daten (keine IP / kein User-Agent).
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
  await server.register(leadRoutes);
  await server.register(analyticsRoutes);
  await server.ready();
  return server;
}

describe('POST /api/leads — Lead-Capture + Vertriebs-Routing', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = await build();
  });
  afterEach(async () => {
    await server.close();
  });

  const validLead = {
    name: 'Erika Mustermann',
    email: 'erika@mustermann-gmbh.de',
    company: 'Mustermann GmbH',
    packageInterest: 'compliance',
    message: 'Wir brauchen einen Scan vor dem ISO-Audit.',
    consent: true,
    utmSource: 'linkedin',
    utmMedium: 'social',
    utmCampaign: 'nis2',
  };

  it('persists the lead and routes it to sales (happy path)', async () => {
    // INSERT ... RETURNING id, dann UPDATE routing_status
    mockQuery
      .mockResolvedValueOnce({ rows: [{ id: 'lead-123' }] } as never)
      .mockResolvedValueOnce({ rows: [] } as never);
    mockSend.mockResolvedValueOnce(true);

    const res = await server.inject({ method: 'POST', url: '/api/leads', payload: validLead });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.success).toBe(true);
    expect(body.data.id).toBe('lead-123');
    expect(body.data.routed).toBe(true);

    // Lead wurde ZUERST persistiert
    expect(mockQuery).toHaveBeenCalled();
    const insertSql = mockQuery.mock.calls[0][0] as string;
    expect(insertSql).toMatch(/INSERT INTO leads/i);

    // Routing an den Vertrieb wurde mit der Lead-ID + E-Mail aufgerufen
    expect(mockSend).toHaveBeenCalledTimes(1);
    expect(mockSend.mock.calls[0][0]).toMatchObject({ id: 'lead-123', email: validLead.email });

    // routing_status -> 'routed'
    const updateParams = mockQuery.mock.calls[1][1] as unknown[];
    expect(updateParams).toEqual(['lead-123', 'routed']);
  });

  it('still stores the lead when sales routing fails (no lead lost)', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [{ id: 'lead-fail' }] } as never)
      .mockResolvedValueOnce({ rows: [] } as never);
    mockSend.mockResolvedValueOnce(false); // z. B. RESEND_API_KEY nicht gesetzt

    const res = await server.inject({ method: 'POST', url: '/api/leads', payload: validLead });

    expect(res.statusCode).toBe(200);
    expect(res.json().data.routed).toBe(false);
    // Lead bleibt gespeichert, Status wird auf 'failed' gesetzt
    expect(mockQuery.mock.calls[1][1]).toEqual(['lead-fail', 'failed']);
  });

  it('rejects a lead without consent (DSGVO)', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/leads',
      payload: { ...validLead, consent: false },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('consent_required');
    expect(mockQuery).not.toHaveBeenCalled();
    expect(mockSend).not.toHaveBeenCalled();
  });

  it('rejects an invalid email', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/leads',
      payload: { ...validLead, email: 'not-an-email' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_email');
  });
});

describe('POST /api/analytics/collect — cookieloses Pageview-Tracking', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = await build();
  });
  afterEach(async () => {
    await server.close();
  });

  it('records a pageview with only anonymous columns (no PII)', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] } as never);

    const res = await server.inject({
      method: 'POST',
      url: '/api/analytics/collect',
      payload: {
        path: '/pricing',
        referrer: 'https://www.google.com/search?q=security+scan',
        utmSource: 'newsletter',
        utmMedium: 'email',
        utmCampaign: 'q2',
      },
    });

    expect(res.statusCode).toBe(204);
    expect(mockQuery).toHaveBeenCalledTimes(1);

    const sql = mockQuery.mock.calls[0][0] as string;
    const params = mockQuery.mock.calls[0][1] as unknown[];

    expect(sql).toMatch(/INSERT INTO analytics_events/i);
    // Nur Host-Domain des Referrers wird gespeichert, nicht die volle URL
    expect(params).toEqual(['pageview', '/pricing', 'www.google.com', 'newsletter', 'email', 'q2']);

    // Sicherheitsnetz: keine personenbezogenen Felder im INSERT
    expect(sql.toLowerCase()).not.toMatch(/\bip\b|user_agent|fingerprint|visitor/);
  });

  it('rejects an external/invalid path', async () => {
    const res = await server.inject({
      method: 'POST',
      url: '/api/analytics/collect',
      payload: { path: 'https://evil.example/inject' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_path');
    expect(mockQuery).not.toHaveBeenCalled();
  });
});
