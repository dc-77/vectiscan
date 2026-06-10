/**
 * VEC-364: Register-Flow erzwingt Firmen-E-Mail + versionierte
 * Scan-Berechtigungs-Bestätigung. Deckt die pure Freemail-Erkennung und die
 * Route-Enforcement (400 ohne Firmen-E-Mail / ohne Consent, 201 mit Speicherung
 * der Version) ab.
 */
import Fastify, { FastifyInstance } from 'fastify';

jest.mock('../lib/db', () => ({ query: jest.fn(), initDb: jest.fn(), pool: { end: jest.fn() } }));
jest.mock('../lib/auth', () => ({
  hashPassword: jest.fn().mockResolvedValue('$2a$12$mockhash'),
  verifyPasswordHash: jest.fn().mockResolvedValue(true),
  generateJwt: jest.fn().mockReturnValue('mock-jwt-token'),
  verifyJwt: jest.fn(),
}));
jest.mock('../lib/audit', () => ({ audit: jest.fn() }));
jest.mock('../lib/email', () => ({ sendPasswordResetEmail: jest.fn() }));

import { isFreemailEmail, AUTHORIZATION_CONSENT_VERSION } from '../lib/authorizationConsent';
import { authRoutes } from '../routes/auth';
import { query } from '../lib/db';

const mockQuery = query as jest.MockedFunction<typeof query>;

describe('isFreemailEmail (VEC-364)', () => {
  it('erkennt Freemail-/Consumer-Provider', () => {
    for (const e of ['a@gmail.com', 'b@gmx.de', 'c@web.de', 'd@outlook.com', 'e@proton.me', 'f@T-Online.de']) {
      expect(isFreemailEmail(e)).toBe(true);
    }
  });
  it('lässt Firmen-E-Mails durch', () => {
    for (const e of ['ceo@acme-corp.de', 'admin@vectigal.tech', 'it@mail-boxes.example.com']) {
      expect(isFreemailEmail(e)).toBe(false);
    }
  });
});

describe('POST /api/auth/register (VEC-364)', () => {
  let server: FastifyInstance;
  beforeEach(async () => {
    jest.clearAllMocks();
    server = Fastify({ logger: false });
    await server.register(authRoutes);
    await server.ready();
  });
  afterEach(() => server.close());

  const body = (over: Record<string, unknown> = {}) => ({
    email: 'admin@acme-corp.de', password: 'supersecret', authorizationConsent: true, ...over,
  });

  it('blockt Freemail-Adressen (400)', async () => {
    const res = await server.inject({ method: 'POST', url: '/api/auth/register', payload: body({ email: 'x@gmail.com' }) });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatch(/Firmen-E-Mail/i);
    expect(mockQuery).not.toHaveBeenCalled();
  });

  it('verlangt die Berechtigungs-Bestätigung (400)', async () => {
    const res = await server.inject({ method: 'POST', url: '/api/auth/register', payload: body({ authorizationConsent: false }) });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatch(/Berechtigungs-Bestätigung/i);
    expect(mockQuery).not.toHaveBeenCalled();
  });

  it('registriert mit Firmen-E-Mail + Consent und speichert die Version (201)', async () => {
    mockQuery
      .mockResolvedValueOnce({ rows: [] } as never)                                  // existing user check
      .mockResolvedValueOnce({ rows: [{ id: 'cust-1' }] } as never)                  // customer upsert
      .mockResolvedValueOnce({ rows: [{ id: 'user-1', email: 'admin@acme-corp.de', role: 'customer' }] } as never); // user insert

    const res = await server.inject({ method: 'POST', url: '/api/auth/register', payload: body() });
    expect(res.statusCode).toBe(201);

    const insertCall = mockQuery.mock.calls.find((c) => /INSERT INTO users/i.test(String(c[0])));
    expect(insertCall).toBeDefined();
    expect(String(insertCall![0])).toMatch(/authorization_consent_version/);
    expect((insertCall![1] as unknown[]).includes(AUTHORIZATION_CONSENT_VERSION)).toBe(true);
  });
});
