import Fastify, { FastifyInstance } from 'fastify';
import { orderRoutes } from '../routes/orders';

// Mock the lib modules
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
}));

jest.mock('../services/VerificationService', () => ({
  generateToken: jest.fn().mockReturnValue('vectiscan-verify-mock12345678'),
  verifyAll: jest.fn(),
}));

import { query } from '../lib/db';
import { scanQueue } from '../lib/queue';

const mockQuery = query as jest.MockedFunction<typeof query>;
const mockScanQueueAdd = scanQueue.add as jest.MockedFunction<typeof scanQueue.add>;

const TEST_UUID = '550e8400-e29b-41d4-a716-446655440000';
const CUST_UUID = 'cust-0000-0000-0000-000000000001';

function mockCustomerResult() {
  return {
    rows: [{ id: CUST_UUID }],
    command: 'INSERT' as const,
    rowCount: 1,
    oid: 0,
    fields: [],
  };
}

function mockInsertResult(pkg: string) {
  return {
    rows: [{ id: TEST_UUID, target_url: 'example.com', status: 'verification_pending', package: pkg, verification_token: 'vectiscan-verify-mock12345678', created_at: new Date() }],
    command: 'INSERT' as const,
    rowCount: 1,
    oid: 0,
    fields: [],
  };
}

function mockOrderRow(pkg: string) {
  return {
    rows: [{
      id: TEST_UUID,
      target_url: 'example.com',
      status: 'created',
      package: pkg,
      customer_id: CUST_UUID,
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
    command: 'SELECT' as const,
    rowCount: 1,
    oid: 0,
    fields: [],
  };
}

const emptyResult = { rows: [], command: 'SELECT' as const, rowCount: 0, oid: 0, fields: [] };

describe('Package selection', () => {
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

  describe('POST /api/orders with package', () => {
    it('should accept package=basic', async () => {
      mockQuery.mockResolvedValueOnce(mockCustomerResult());
      mockQuery.mockResolvedValueOnce(mockInsertResult('basic'));

      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com', email: 'test@example.com', package: 'basic' },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.package).toBe('basic');
    });

    it('should accept package=professional', async () => {
      mockQuery.mockResolvedValueOnce(mockCustomerResult());
      mockQuery.mockResolvedValueOnce(mockInsertResult('professional'));

      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com', email: 'test@example.com', package: 'professional' },
      });

      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('professional');
    });

    it('should accept package=nis2', async () => {
      mockQuery.mockResolvedValueOnce(mockCustomerResult());
      mockQuery.mockResolvedValueOnce(mockInsertResult('nis2'));

      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com', email: 'test@example.com', package: 'nis2' },
      });

      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('nis2');
    });

    it('should reject invalid package', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com', email: 'test@example.com', package: 'invalid' },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error).toBe('Invalid package. Must be basic, professional, or nis2.');
    });

    it('should default to professional when no package specified', async () => {
      mockQuery.mockResolvedValueOnce(mockCustomerResult());
      mockQuery.mockResolvedValueOnce(mockInsertResult('professional'));

      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com', email: 'test@example.com' },
      });

      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('professional');
    });

    it('should not queue scan job (verification required first)', async () => {
      mockQuery.mockResolvedValueOnce(mockCustomerResult());
      mockQuery.mockResolvedValueOnce(mockInsertResult('nis2'));

      await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com', email: 'test@example.com', package: 'nis2' },
      });

      expect(mockScanQueueAdd).not.toHaveBeenCalled();
    });
  });

  describe('GET /api/orders/:id with package', () => {
    it('should return package and estimatedDuration for basic', async () => {
      mockQuery
        .mockResolvedValueOnce(mockOrderRow('basic'))
        .mockResolvedValueOnce(emptyResult);

      const res = await server.inject({ method: 'GET', url: `/api/orders/${TEST_UUID}` });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.package).toBe('basic');
      expect(body.data.estimatedDuration).toBe('~10 Minuten');
    });

    it('should return package and estimatedDuration for professional', async () => {
      mockQuery
        .mockResolvedValueOnce(mockOrderRow('professional'))
        .mockResolvedValueOnce(emptyResult);

      const res = await server.inject({ method: 'GET', url: `/api/orders/${TEST_UUID}` });
      const body = res.json();
      expect(body.data.package).toBe('professional');
      expect(body.data.estimatedDuration).toBe('~45 Minuten');
    });

    it('should return package and estimatedDuration for nis2', async () => {
      mockQuery
        .mockResolvedValueOnce(mockOrderRow('nis2'))
        .mockResolvedValueOnce(emptyResult);

      const res = await server.inject({ method: 'GET', url: `/api/orders/${TEST_UUID}` });
      const body = res.json();
      expect(body.data.package).toBe('nis2');
      expect(body.data.estimatedDuration).toBe('~45 Minuten');
    });
  });
});
