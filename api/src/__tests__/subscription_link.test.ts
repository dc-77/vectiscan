import Fastify, { FastifyInstance } from 'fastify';
import { orderRoutes } from '../routes/orders';

// Reuse the mock setup pattern from routes.test.ts
jest.mock('../lib/db', () => ({
  query: jest.fn(),
  initDb: jest.fn(),
  pool: { end: jest.fn() },
}));

jest.mock('../lib/queue', () => ({
  scanQueue: { add: jest.fn() },
  reportQueue: { add: jest.fn() },
  publishEvent: jest.fn(),
  getProgressFromRedis: jest.fn().mockResolvedValue(null),
}));

jest.mock('../lib/minio', () => ({
  minioClient: { getObject: jest.fn(), removeObject: jest.fn() },
  initBuckets: jest.fn(),
  getPresignedUrl: jest.fn(),
}));

jest.mock('../lib/validate', () => ({
  isValidDomain: jest.fn((d: string) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)),
  isValidTarget: jest.fn((d: unknown) => typeof d === 'string' && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d) ? d.toLowerCase() : null),
}));

jest.mock('../services/VerificationService', () => ({
  generateToken: jest.fn().mockReturnValue('vectiscan-verify-mock'),
  verifyAll: jest.fn(),
}));

jest.mock('../lib/auth', () => ({
  hashPassword: jest.fn().mockResolvedValue('hash'),
  verifyPasswordHash: jest.fn().mockResolvedValue(true),
  generateJwt: jest.fn().mockReturnValue('mock-jwt'),
  verifyJwt: jest.fn().mockReturnValue({
    sub: 'user-1', role: 'customer', customerId: 'cust-1', email: 'c@example.com',
  }),
}));

jest.mock('../lib/audit', () => ({ audit: jest.fn() }));
jest.mock('../lib/email', () => ({ sendScanCompleteEmail: jest.fn(), sendPasswordResetEmail: jest.fn() }));

import { query } from '../lib/db';
import { scanQueue } from '../lib/queue';

const mockQuery = query as jest.MockedFunction<typeof query>;
const AUTH = { authorization: 'Bearer mock-jwt' };

describe('POST /api/orders — auto-link to subscription', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = Fastify({ logger: false });
    await server.register(orderRoutes);
    await server.ready();
  });

  afterEach(async () => {
    await server.close();
  });

  it('attaches subscription_id when an active subscription covers the domain', async () => {
    // 1: verified_domains check — already verified (so we go straight to queued + scan enqueue path)
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'vd-1', verification_method: 'manual', expires_at: new Date(Date.now() + 86400000) }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] });
    // 2: subscription auto-link — found
    mockQuery.mockResolvedValueOnce({ rows: [{ id: 'sub-1' }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] });
    // 3: INSERT order returning subscription_id
    mockQuery.mockResolvedValueOnce({
      rows: [{
        id: 'ord-1', target_url: 'example.com', status: 'queued', package: 'perimeter',
        verification_token: '', created_at: new Date(), subscription_id: 'sub-1',
      }],
      command: 'INSERT', rowCount: 1, oid: 0, fields: [],
    });

    const res = await server.inject({
      method: 'POST', url: '/api/orders', headers: AUTH,
      payload: { domain: 'example.com', package: 'perimeter' },
    });

    expect(res.statusCode).toBe(201);
    // Confirm the subscription lookup ran with the right params
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('FROM subscriptions s'),
      ['cust-1', 'example.com'],
    );
    // Confirm the INSERT carried the subscription_id we returned from the lookup
    const insertCall = mockQuery.mock.calls.find(c => typeof c[0] === 'string' && c[0].includes('INSERT INTO orders'));
    expect(insertCall).toBeDefined();
    expect(insertCall![1]).toEqual(expect.arrayContaining(['sub-1']));
    expect(scanQueue.add).toHaveBeenCalled();
  });

  it('leaves subscription_id null when no active subscription matches', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
    mockQuery.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
    mockQuery.mockResolvedValueOnce({
      rows: [{
        id: 'ord-2', target_url: 'other.com', status: 'verification_pending', package: 'perimeter',
        verification_token: 'tok', created_at: new Date(), subscription_id: null,
      }],
      command: 'INSERT', rowCount: 1, oid: 0, fields: [],
    });

    const res = await server.inject({
      method: 'POST', url: '/api/orders', headers: AUTH,
      payload: { domain: 'other.com' },
    });

    expect(res.statusCode).toBe(201);
    const insertCall = mockQuery.mock.calls.find(c => typeof c[0] === 'string' && c[0].includes('INSERT INTO orders'));
    expect(insertCall).toBeDefined();
    // subscription_id should NOT be in the column list (between INSERT INTO orders ( … ))
    const sql = insertCall![0] as string;
    const colsMatch = sql.match(/INSERT INTO orders \(([^)]+)\)/);
    expect(colsMatch).not.toBeNull();
    expect(colsMatch![1]).not.toContain('subscription_id');
    // Params must NOT include any value that looks like a subscription id ('sub-1' etc.)
    expect(insertCall![1] as unknown[]).not.toContain('sub-1');
  });
});
