import Fastify, { FastifyInstance } from 'fastify';
import { orderRoutes } from '../routes/orders';

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
  enqueuePrecheck: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../lib/minio', () => {
  const { Readable } = require('stream');
  return {
    minioClient: {
      getObject: jest.fn().mockResolvedValue(Readable.from(Buffer.from('fake-pdf'))),
    },
    initBuckets: jest.fn(),
    getPresignedUrl: jest.fn(),
  };
});

jest.mock('../lib/validate', () => ({
  isValidDomain: jest.fn((d: string) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)),
  isValidTarget: jest.fn((d: unknown) => {
    if (typeof d !== 'string') return null;
    if (/^[a-z]+:\/\//i.test(d)) return null;
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) return d.toLowerCase();
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(d)) return d;
    return null;
  }),
  validateTargetBatch: jest.fn((inputs: Array<{ raw_input?: unknown }>) => ({
    targets: inputs.map(i => ({
      raw_input: String(i?.raw_input ?? ''),
      valid: true,
      canonical: String(i?.raw_input ?? '').toLowerCase(),
      target_type: 'fqdn_root',
      policy_default: 'enumerate',
      warnings: [],
    })),
    errors: [],
  })),
}));

jest.mock('../services/VerificationService', () => ({
  generateToken: jest.fn().mockReturnValue('vectiscan-verify-mock12345678'),
  verifyAll: jest.fn(),
}));

jest.mock('../lib/auth', () => ({
  hashPassword: jest.fn().mockResolvedValue('$2a$12$mockhash'),
  verifyPasswordHash: jest.fn().mockResolvedValue(true),
  generateJwt: jest.fn().mockReturnValue('mock-jwt-token'),
  verifyJwt: jest.fn().mockReturnValue({
    sub: 'user-uuid-1234',
    role: 'admin',
    customerId: 'cust-0000-0000-0000-000000000001',
    email: 'admin@test.com',
  }),
}));

jest.mock('../lib/audit', () => ({ audit: jest.fn().mockResolvedValue(undefined) }));

import { query } from '../lib/db';
import { scanQueue } from '../lib/queue';

const mockQuery = query as jest.MockedFunction<typeof query>;
const mockScanQueueAdd = scanQueue.add as jest.MockedFunction<typeof scanQueue.add>;

const ORDER_UUID = '550e8400-e29b-41d4-a716-446655440000';
const TARGET_UUID = '650e8400-e29b-41d4-a716-446655440000';
const AUTH_HEADER = { authorization: 'Bearer mock-jwt-token' };

function mockOrderRow(pkg: string) {
  return {
    rows: [{
      id: ORDER_UUID,
      target_url: 'example.com',
      status: 'precheck_running',
      package: pkg,
      customer_id: 'cust-0000-0000-0000-000000000001',
      discovered_hosts: null,
      hosts_total: 0,
      hosts_completed: 0,
      current_phase: null,
      current_tool: null,
      current_host: null,
      scan_started_at: null,
      scan_finished_at: null,
      error_message: null,
      created_at: new Date(),
    }],
    command: 'SELECT' as const, rowCount: 1, oid: 0, fields: [],
  };
}

const emptyResult = { rows: [], command: 'SELECT' as const, rowCount: 0, oid: 0, fields: [] };

describe('Package selection (v2: 6 packages, Multi-Target)', () => {
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

  // POST /api/orders Multi-Target-Flow: INSERT orders → INSERT scan_targets
  function chainOrderInsert(pkg: string) {
    mockQuery.mockResolvedValueOnce({
      rows: [{ id: ORDER_UUID, status: 'precheck_running', package: pkg, created_at: new Date() }],
      command: 'INSERT' as const, rowCount: 1, oid: 0, fields: [],
    });
    mockQuery.mockResolvedValueOnce({
      rows: [{ id: TARGET_UUID }],
      command: 'INSERT' as const, rowCount: 1, oid: 0, fields: [],
    });
  }

  describe('POST /api/orders with package', () => {
    it('should accept package=webcheck', async () => {
      chainOrderInsert('webcheck');
      const res = await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { package: 'webcheck', targets: [{ raw_input: 'example.com' }] },
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('webcheck');
    });

    it('should accept package=perimeter', async () => {
      chainOrderInsert('perimeter');
      const res = await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { package: 'perimeter', targets: [{ raw_input: 'example.com' }] },
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('perimeter');
    });

    it('should accept package=compliance', async () => {
      chainOrderInsert('compliance');
      const res = await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { package: 'compliance', targets: [{ raw_input: 'example.com' }] },
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('compliance');
    });

    it('should accept package=supplychain', async () => {
      chainOrderInsert('supplychain');
      const res = await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { package: 'supplychain', targets: [{ raw_input: 'example.com' }] },
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('supplychain');
    });

    it('should accept package=insurance', async () => {
      chainOrderInsert('insurance');
      const res = await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { package: 'insurance', targets: [{ raw_input: 'example.com' }] },
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('insurance');
    });

    it('should accept package=tlscompliance', async () => {
      chainOrderInsert('tlscompliance');
      const res = await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { package: 'tlscompliance', targets: [{ raw_input: 'example.com' }] },
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('tlscompliance');
    });

    it('should reject invalid package', async () => {
      const res = await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { package: 'invalid', targets: [{ raw_input: 'example.com' }] },
      });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toContain('Invalid package');
    });

    it('should reject legacy package names (basic, professional, nis2)', async () => {
      for (const legacyPkg of ['basic', 'professional', 'nis2']) {
        const res = await server.inject({
          method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
          payload: { package: legacyPkg, targets: [{ raw_input: 'example.com' }] },
        });
        expect(res.statusCode).toBe(400);
      }
    });

    it('should default to perimeter when no package specified', async () => {
      chainOrderInsert('perimeter');
      const res = await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { targets: [{ raw_input: 'example.com' }] },
      });
      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('perimeter');
    });

    it('should not queue scan job (admin review required first)', async () => {
      chainOrderInsert('compliance');
      await server.inject({
        method: 'POST', url: '/api/orders', headers: AUTH_HEADER,
        payload: { package: 'compliance', targets: [{ raw_input: 'example.com' }] },
      });
      expect(mockScanQueueAdd).not.toHaveBeenCalled();
    });
  });

  describe('GET /api/orders/:id with package', () => {
    it('should return package and estimatedDuration for webcheck', async () => {
      mockQuery.mockResolvedValueOnce(mockOrderRow('webcheck')).mockResolvedValueOnce(emptyResult);
      const res = await server.inject({ method: 'GET', url: `/api/orders/${ORDER_UUID}`, headers: AUTH_HEADER });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.package).toBe('webcheck');
      expect(body.data.estimatedDuration).toBe('~15–20 Minuten');
    });

    it('should return package and estimatedDuration for perimeter', async () => {
      mockQuery.mockResolvedValueOnce(mockOrderRow('perimeter')).mockResolvedValueOnce(emptyResult);
      const res = await server.inject({ method: 'GET', url: `/api/orders/${ORDER_UUID}`, headers: AUTH_HEADER });
      expect(res.json().data.package).toBe('perimeter');
      expect(res.json().data.estimatedDuration).toBe('~60–90 Minuten');
    });

    it('should return package and estimatedDuration for compliance', async () => {
      mockQuery.mockResolvedValueOnce(mockOrderRow('compliance')).mockResolvedValueOnce(emptyResult);
      const res = await server.inject({ method: 'GET', url: `/api/orders/${ORDER_UUID}`, headers: AUTH_HEADER });
      expect(res.json().data.package).toBe('compliance');
      expect(res.json().data.estimatedDuration).toBe('~65–95 Minuten');
    });
  });
});
