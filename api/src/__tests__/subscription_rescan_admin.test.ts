import Fastify, { FastifyInstance } from 'fastify';
import { subscriptionRoutes } from '../routes/subscriptions';

jest.mock('../lib/db', () => ({
  query: jest.fn(),
  initDb: jest.fn(),
  pool: { end: jest.fn() },
}));

jest.mock('../lib/queue', () => ({
  scanQueue: { add: jest.fn() },
  reportQueue: { add: jest.fn() },
  publishEvent: jest.fn(),
}));

const mockVerifyJwt = jest.fn();
jest.mock('../lib/auth', () => ({
  hashPassword: jest.fn(),
  verifyPasswordHash: jest.fn(),
  generateJwt: jest.fn(),
  verifyJwt: (...args: unknown[]) => mockVerifyJwt(...args),
}));

jest.mock('../lib/audit', () => ({ audit: jest.fn() }));

import { query } from '../lib/db';
import { scanQueue } from '../lib/queue';

const mockQuery = query as jest.MockedFunction<typeof query>;
const SUB_ID = '550e8400-e29b-41d4-a716-446655440000';
const AUTH = { authorization: 'Bearer mock-jwt' };

function asUser(role: 'admin' | 'customer') {
  mockVerifyJwt.mockReturnValue({
    sub: 'user-x', role, customerId: 'cust-1', email: `${role}@example.com`,
  });
}

describe('POST /api/subscriptions/:id/rescan — admin bypass', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = Fastify({ logger: { level: 'error' } });
    await server.register(subscriptionRoutes);
    await server.ready();
  });

  afterEach(async () => { await server.close(); });

  it('rejects customer rescan when quota is exhausted', async () => {
    asUser('customer');
    // 1: subscription lookup — quota fully used
    mockQuery.mockResolvedValueOnce({
      rows: [{ customer_id: 'cust-1', package: 'perimeter', max_rescans: 3, rescans_used: 3, status: 'active' }],
      command: 'SELECT', rowCount: 1, oid: 0, fields: [],
    });

    const res = await server.inject({
      method: 'POST', url: `/api/subscriptions/${SUB_ID}/rescan`,
      headers: AUTH, payload: { domain: 'example.com' },
    });

    expect(res.statusCode).toBe(409);
    expect(scanQueue.add).not.toHaveBeenCalled();
  });

  it('allows admin rescan even when quota is exhausted, without incrementing rescans_used', async () => {
    asUser('admin');
    // 1: subscription lookup — quota fully used
    mockQuery.mockResolvedValueOnce({
      rows: [{ customer_id: 'cust-1', package: 'perimeter', max_rescans: 3, rescans_used: 3, status: 'active' }],
      command: 'SELECT', rowCount: 1, oid: 0, fields: [],
    });
    // 2: domain check — verified + enabled
    mockQuery.mockResolvedValueOnce({
      rows: [{ domain: 'example.com' }],
      command: 'SELECT', rowCount: 1, oid: 0, fields: [],
    });
    // 3: INSERT order
    mockQuery.mockResolvedValueOnce({
      rows: [{ id: 'order-new' }],
      command: 'INSERT', rowCount: 1, oid: 0, fields: [],
    });

    const res = await server.inject({
      method: 'POST', url: `/api/subscriptions/${SUB_ID}/rescan`,
      headers: AUTH, payload: { domain: 'example.com' },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.data.message).toMatch(/Admin-Re-Scan/i);

    // The UPDATE that increments rescans_used must NOT have run for an admin
    const updateCall = mockQuery.mock.calls.find(c =>
      typeof c[0] === 'string' && c[0].includes('rescans_used = rescans_used + 1'));
    expect(updateCall).toBeUndefined();

    expect(scanQueue.add).toHaveBeenCalled();
  });

  it('increments rescans_used for customer rescan within quota', async () => {
    asUser('customer');
    mockQuery.mockResolvedValueOnce({
      rows: [{ customer_id: 'cust-1', package: 'perimeter', max_rescans: 3, rescans_used: 1, status: 'active' }],
      command: 'SELECT', rowCount: 1, oid: 0, fields: [],
    });
    mockQuery.mockResolvedValueOnce({
      rows: [{ domain: 'example.com' }],
      command: 'SELECT', rowCount: 1, oid: 0, fields: [],
    });
    mockQuery.mockResolvedValueOnce({
      rows: [{ id: 'order-new' }],
      command: 'INSERT', rowCount: 1, oid: 0, fields: [],
    });
    mockQuery.mockResolvedValueOnce({
      rows: [], command: 'UPDATE', rowCount: 1, oid: 0, fields: [],
    });

    const res = await server.inject({
      method: 'POST', url: `/api/subscriptions/${SUB_ID}/rescan`,
      headers: AUTH, payload: { domain: 'example.com' },
    });

    expect(res.statusCode).toBe(200);
    const updateCall = mockQuery.mock.calls.find(c =>
      typeof c[0] === 'string' && c[0].includes('rescans_used = rescans_used + 1'));
    expect(updateCall).toBeDefined();
  });
});
