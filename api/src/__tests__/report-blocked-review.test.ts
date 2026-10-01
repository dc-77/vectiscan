import Fastify, { FastifyInstance } from 'fastify';
import { readFileSync } from 'fs';
import { join } from 'path';

// S5: Defektliste, Beobachtungen ohne Regel und Kundenkontext im Admin-Review.
// Aufbau wie routes.test.ts: echte Fastify-Instanz, alle Bibliotheken gemockt,
// keine Datenbank.

jest.mock('../lib/db', () => ({
  query: jest.fn(),
  initDb: jest.fn(),
  pool: { end: jest.fn() },
}));

jest.mock('../lib/queue', () => ({
  scanQueue: { add: jest.fn() },
  reportQueue: { add: jest.fn() },
  publishEvent: jest.fn().mockResolvedValue(undefined),
  getProgressFromRedis: jest.fn().mockResolvedValue(null),
  enqueuePrecheck: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../lib/minio', () => ({
  minioClient: { putObject: jest.fn(), removeObject: jest.fn(), getObject: jest.fn() },
  initBuckets: jest.fn(),
  getPresignedUrl: jest.fn(),
}));

jest.mock('../lib/auth', () => ({
  hashPassword: jest.fn(),
  verifyPasswordHash: jest.fn(),
  generateJwt: jest.fn().mockReturnValue('mock-jwt-token'),
  verifyJwt: jest.fn().mockReturnValue({
    sub: 'user-uuid-1234', role: 'admin',
    customerId: 'cust-uuid-1234', email: 'admin@test.com',
  }),
}));

jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import { query } from '../lib/db';
import { adminReviewRoutes } from '../routes/admin-review';
import { sanitizeCustomerContext } from '../lib/customerContext';

const mockQuery = query as jest.MockedFunction<typeof query>;
const AUTH_HEADER = { authorization: 'Bearer mock-jwt-token' };
const ORDER_ID = '11111111-2222-3333-4444-555555555555';

/** Antwort fuer eine Abfrage stellen, ohne die Reihenfolge zu raten. */
function rowsFor(matcher: RegExp, rows: unknown[]) {
  return { matcher, rows };
}

function mockQueries(plan: Array<{ matcher: RegExp; rows: unknown[] }>) {
  mockQuery.mockImplementation(((sql: string) => {
    const hit = plan.find(p => p.matcher.test(sql));
    return Promise.resolve({ rows: hit ? hit.rows : [], rowCount: hit ? hit.rows.length : 0 });
  }) as unknown as typeof query);
}

const DEFECTS_PAYLOAD = {
  engine: 'v3',
  level: 'strict',
  blocked_at: '2026-09-20T18:00:00+00:00',
  defects: [
    {
      engine: 'v3', check: 'abdeckungskapitel_leer', severity: 'error',
      message: 'Kapitel 2 nennt fuer keinen Host eine Abdeckung.', finding_id: null, detail: {},
    },
    {
      engine: 'v2', check: 'ids', severity: 'error',
      message: 'Luecke zwischen 003 und 005', finding_id: 'VS-2026-004', detail: {},
    },
  ],
  unprocessed: [
    { quelle: 'katalog', kind: 'service_unknown_port', what: '1.2.3.4:2052', count: 1 },
  ],
  counts: { errors: 2, warnings: 0, unprocessed: 1 },
};

describe('S5 — Admin-Review liefert den Berichtsstand', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = Fastify({ logger: false });
    await server.register(adminReviewRoutes);
    await server.ready();
  });

  afterEach(async () => {
    await server.close();
  });

  it('liefert Defektliste, Beobachtungen und Kundenkontext der Order', async () => {
    mockQueries([
      rowsFor(/FROM scan_targets/, []),
      rowsFor(/FROM scan_target_hosts/, []),
      rowsFor(/FROM scan_authorizations/, []),
      rowsFor(/report_defects, customer_context FROM orders/, [{
        status: 'report_blocked',
        report_defects: DEFECTS_PAYLOAD,
        customer_context: { firmenname: 'Beispiel GmbH', sources: { firmenname: { source: 'kunde' } } },
      }]),
    ]);

    const res = await server.inject({
      method: 'GET', url: `/api/admin/review/order/${ORDER_ID}`, headers: AUTH_HEADER,
    });

    expect(res.statusCode).toBe(200);
    const report = res.json().data.report;
    expect(report.status).toBe('report_blocked');
    expect(report.blockedAt).toBe('2026-09-20T18:00:00+00:00');
    expect(report.counts).toEqual({ errors: 2, warnings: 0, unprocessed: 1 });
    // Beide Engines stehen in derselben Liste, unterscheidbar am Eintrag.
    expect(report.defects.map((d: { engine: string }) => d.engine)).toEqual(['v3', 'v2']);
    expect(report.unprocessed[0].quelle).toBe('katalog');
    expect(report.customerContext.firmenname).toBe('Beispiel GmbH');
  });

  it('S7a Punkt 8 (E27): liefert Fristhinweise fuer eine Freigabe heute', async () => {
    jest.useFakeTimers({ now: new Date('2026-09-27T10:00:00Z'), doNotFake: ['nextTick', 'setImmediate'] });
    try {
      mockQueries([
        rowsFor(/FROM scan_targets/, []),
        rowsFor(/FROM scan_target_hosts/, []),
        rowsFor(/FROM scan_authorizations/, []),
        rowsFor(/report_defects, customer_context FROM orders/, [{
          status: 'pending_review',
          report_defects: {
            ...DEFECTS_PAYLOAD,
            fristen_scantag: '2026-09-23',
            fristen_schwellen: { sofort: 7, bald: 14, spaeter: 30, domain: 30 },
            fristen: [{ art: 'tls', subjekt: 'online.heuel.com:443', gueltig_bis: '2026-10-25', tage_scantag: 31 }],
          },
          customer_context: null,
        }]),
      ]);

      const res = await server.inject({
        method: 'GET', url: `/api/admin/review/order/${ORDER_ID}`, headers: AUTH_HEADER,
      });

      expect(res.statusCode).toBe(200);
      const hints = res.json().data.report.deadlineHints;
      expect(hints).toHaveLength(1);
      expect(hints[0]).toMatchObject({ subjekt: 'online.heuel.com:443', tageFreigabe: 27,
                                       regelFreigabe: 'cert_expiring_later', freigabetag: '2026-09-27' });
    } finally {
      jest.useRealTimers();
    }
  });

  it('faellt fuer alte Laeufe auf reports.validation_warnings zurueck', async () => {
    mockQueries([
      rowsFor(/FROM scan_targets/, []),
      rowsFor(/FROM scan_target_hosts/, []),
      rowsFor(/FROM scan_authorizations/, []),
      rowsFor(/report_defects, customer_context FROM orders/, [{
        status: 'pending_review', report_defects: null, customer_context: null,
      }]),
      rowsFor(/validation_warnings FROM reports/, [{
        validation_warnings: {
          passed: false, level: 'warn',
          errors: [{ check: 'ids', severity: 'error', finding_id: 'VS-2026-004', message: 'Luecke' }],
          warnings: [], error_count: 1, warning_count: 0,
        },
      }]),
    ]);

    const res = await server.inject({
      method: 'GET', url: `/api/admin/review/order/${ORDER_ID}`, headers: AUTH_HEADER,
    });

    const report = res.json().data.report;
    expect(report.engine).toBe('v2');
    expect(report.defects).toHaveLength(1);
    expect(report.defects[0].engine).toBe('v2');
    expect(report.counts.errors).toBe(1);
  });

  it('liefert fuer Subscriptions keinen Berichtsstand', async () => {
    mockQueries([
      rowsFor(/FROM scan_targets/, []),
      rowsFor(/FROM scan_target_hosts/, []),
      rowsFor(/FROM scan_authorizations/, []),
    ]);

    const res = await server.inject({
      method: 'GET', url: `/api/admin/review/subscription/${ORDER_ID}`, headers: AUTH_HEADER,
    });

    expect(res.json().data.report).toBeNull();
  });

  it('speichert den Kundenkontext mit Quelle admin', async () => {
    mockQueries([
      rowsFor(/SELECT customer_context FROM orders/, [{
        customer_context: { branche: 'Maschinenbau', sources: { branche: { source: 'recherche', url: 'https://x.de' } } },
      }]),
      rowsFor(/UPDATE orders SET customer_context/, []),
    ]);

    const res = await server.inject({
      method: 'PUT', url: `/api/admin/orders/${ORDER_ID}/customer-context`,
      headers: AUTH_HEADER, payload: { firmenname: 'Beispiel GmbH', branche: '' },
    });

    expect(res.statusCode).toBe(200);
    const context = res.json().data.customerContext;
    expect(context.firmenname).toBe('Beispiel GmbH');
    expect(context.sources.firmenname).toEqual({ source: 'admin' });
    // Geleertes Feld ist weg, samt Herkunft — die Recherche darf es wieder fuellen.
    expect(context.branche).toBeUndefined();
    expect(context.sources.branche).toBeUndefined();
  });

  it('weist eine unbekannte Order ab', async () => {
    mockQueries([rowsFor(/SELECT customer_context FROM orders/, [])]);

    const res = await server.inject({
      method: 'PUT', url: `/api/admin/orders/${ORDER_ID}/customer-context`,
      headers: AUTH_HEADER, payload: { firmenname: 'Beispiel GmbH' },
    });

    expect(res.statusCode).toBe(404);
  });
});

describe('S5 — report_blocked ist regenerierbar', () => {
  it('steht in der Statusliste von /regenerate-report', () => {
    // Statisch geprueft: die Route selbst braucht die halbe orders.ts-Mockkette,
    // und was hier zaehlt, ist allein die Liste.
    const source = readFileSync(
      join(__dirname, '..', 'routes', 'orders.ts'), 'utf-8');
    const liste = source.slice(source.indexOf('const allowedStatuses'),
                               source.indexOf('if (!allowedStatuses.includes'));
    expect(liste).toContain("'report_blocked'");
  });

  it('gibt die Defektliste im Order-Detail an Admins aus', () => {
    const source = readFileSync(
      join(__dirname, '..', 'routes', 'orders.ts'), 'utf-8');
    expect(source).toContain('o.report_defects');
    expect(source).toContain('reportDefects: isAdmin ? (order.report_defects ?? null) : undefined');
  });
});

describe('S5 — sanitizeCustomerContext', () => {
  it('nimmt nur bekannte Felder und setzt die Quelle', () => {
    const context = sanitizeCustomerContext(
      { firmenname: '  Beispiel   GmbH ', branche: 'Maschinenbau', boesartig: 'weg' },
      'kunde');

    expect(context.firmenname).toBe('Beispiel GmbH');
    expect(context).not.toHaveProperty('boesartig');
    expect(context.sources).toEqual({
      firmenname: { source: 'kunde' }, branche: { source: 'kunde' },
    });
  });

  it('laesst nicht genannte Felder samt Herkunft stehen', () => {
    const previous = {
      firmenname: 'Alt GmbH', branche: 'Handel',
      sources: { firmenname: { source: 'kunde' as const }, branche: { source: 'recherche' as const, url: 'https://x.de' } },
    };

    const context = sanitizeCustomerContext({ branche: 'Maschinenbau' }, 'admin', previous);

    expect(context.firmenname).toBe('Alt GmbH');
    expect(context.sources?.firmenname).toEqual({ source: 'kunde' });
    expect(context.branche).toBe('Maschinenbau');
    expect(context.sources?.branche).toEqual({ source: 'admin' });
  });

  it('verwirft Systeme ohne Hostname oder Zweck', () => {
    const context = sanitizeCustomerContext({
      systeme: [
        { fqdn: 'WWW.Beispiel.DE', zweck: ' Unternehmenswebsite ' },
        { fqdn: '', zweck: 'ohne Namen' },
        { fqdn: 'shop.beispiel.de', zweck: '' },
        'unsinn',
      ],
    }, 'admin');

    expect(context.systeme).toEqual([{ fqdn: 'www.beispiel.de', zweck: 'Unternehmenswebsite' }]);
  });

  it('S6b-1 (spec/09 Q15): Kurzname ist ein eigenes Feld mit Herkunft', () => {
    const previous = {
      firmenname: 'Junkerwerk Linder GmbH + Co. KG', kurzname: 'Junkerwerk Linder',
      sources: { firmenname: { source: 'recherche' as const, url: 'https://x.de' },
                 kurzname: { source: 'recherche' as const, url: 'https://x.de' } },
    };

    const bleibt = sanitizeCustomerContext({ branche: 'Metall' }, 'admin', previous);
    expect(bleibt.kurzname).toBe('Junkerwerk Linder');
    expect(bleibt.sources?.kurzname?.source).toBe('recherche');

    const gesetzt = sanitizeCustomerContext({ kurzname: '  Hündgen Entsorgung ' }, 'admin', previous);
    expect(gesetzt.kurzname).toBe('Hündgen Entsorgung');
    expect(gesetzt.sources?.kurzname).toEqual({ source: 'admin' });
  });
});
