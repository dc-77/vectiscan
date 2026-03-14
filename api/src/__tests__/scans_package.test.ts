import Fastify, { FastifyInstance } from 'fastify';
import { scanRoutes } from '../routes/scans';

// Mock the lib modules
jest.mock('../lib/db', () => ({
  query: jest.fn(),
  initDb: jest.fn(),
  pool: { end: jest.fn() },
}));

jest.mock('../lib/queue', () => ({
  scanQueue: { add: jest.fn() },
  reportQueue: { add: jest.fn() },
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

import { query } from '../lib/db';
import { scanQueue } from '../lib/queue';

const mockQuery = query as jest.MockedFunction<typeof query>;
const mockScanQueueAdd = scanQueue.add as jest.MockedFunction<typeof scanQueue.add>;

const TEST_UUID = '550e8400-e29b-41d4-a716-446655440000';

function mockInsertResult(pkg: string) {
  return {
    rows: [{ id: TEST_UUID, domain: 'example.com', status: 'created', package: pkg, created_at: new Date() }],
    command: 'INSERT' as const,
    rowCount: 1,
    oid: 0,
    fields: [],
  };
}

function mockScanRow(pkg: string) {
  return {
    rows: [{
      id: TEST_UUID,
      domain: 'example.com',
      status: 'created',
      package: pkg,
      discovered_hosts: null,
      hosts_total: 0,
      hosts_completed: 0,
      current_phase: null,
      current_tool: null,
      current_host: null,
      started_at: null,
      finished_at: null,
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
    await server.register(scanRoutes);
    await server.ready();
  });

  afterEach(async () => {
    await server.close();
  });

  describe('POST /api/scans with package', () => {
    it('should accept package=basic', async () => {
      mockQuery.mockResolvedValueOnce(mockInsertResult('basic'));
      mockScanQueueAdd.mockResolvedValueOnce({} as never);

      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com', package: 'basic' },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.package).toBe('basic');
    });

    it('should accept package=professional', async () => {
      mockQuery.mockResolvedValueOnce(mockInsertResult('professional'));
      mockScanQueueAdd.mockResolvedValueOnce({} as never);

      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com', package: 'professional' },
      });

      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('professional');
    });

    it('should accept package=nis2', async () => {
      mockQuery.mockResolvedValueOnce(mockInsertResult('nis2'));
      mockScanQueueAdd.mockResolvedValueOnce({} as never);

      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com', package: 'nis2' },
      });

      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('nis2');
    });

    it('should reject invalid package', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com', package: 'invalid' },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error).toBe('Invalid package. Must be basic, professional, or nis2.');
    });

    it('should default to professional when no package specified', async () => {
      mockQuery.mockResolvedValueOnce(mockInsertResult('professional'));
      mockScanQueueAdd.mockResolvedValueOnce({} as never);

      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com' },
      });

      expect(res.statusCode).toBe(201);
      expect(res.json().data.package).toBe('professional');
      // Verify DB was called with 'professional'
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO scans'),
        ['example.com', 'professional'],
      );
    });

    it('should include package in queue payload', async () => {
      mockQuery.mockResolvedValueOnce(mockInsertResult('nis2'));
      mockScanQueueAdd.mockResolvedValueOnce({} as never);

      await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com', package: 'nis2' },
      });

      expect(mockScanQueueAdd).toHaveBeenCalledWith('scan', {
        scanId: TEST_UUID,
        targetDomain: 'example.com',
        package: 'nis2',
      });
    });
  });

  describe('GET /api/scans/:id with package', () => {
    it('should return package and estimatedDuration for basic', async () => {
      mockQuery
        .mockResolvedValueOnce(mockScanRow('basic'))
        .mockResolvedValueOnce(emptyResult);

      const res = await server.inject({ method: 'GET', url: `/api/scans/${TEST_UUID}` });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.data.package).toBe('basic');
      expect(body.data.estimatedDuration).toBe('~10 Minuten');
    });

    it('should return package and estimatedDuration for professional', async () => {
      mockQuery
        .mockResolvedValueOnce(mockScanRow('professional'))
        .mockResolvedValueOnce(emptyResult);

      const res = await server.inject({ method: 'GET', url: `/api/scans/${TEST_UUID}` });
      const body = res.json();
      expect(body.data.package).toBe('professional');
      expect(body.data.estimatedDuration).toBe('~45 Minuten');
    });

    it('should return package and estimatedDuration for nis2', async () => {
      mockQuery
        .mockResolvedValueOnce(mockScanRow('nis2'))
        .mockResolvedValueOnce(emptyResult);

      const res = await server.inject({ method: 'GET', url: `/api/scans/${TEST_UUID}` });
      const body = res.json();
      expect(body.data.package).toBe('nis2');
      expect(body.data.estimatedDuration).toBe('~45 Minuten');
    });
  });
});
