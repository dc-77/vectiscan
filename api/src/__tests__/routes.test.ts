import Fastify, { FastifyInstance } from 'fastify';
import { healthRoutes } from '../routes/health';
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
      getObject: jest.fn().mockResolvedValue(Readable.from(Buffer.from('fake-pdf-content'))),
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
import { getPresignedUrl } from '../lib/minio';

const mockQuery = query as jest.MockedFunction<typeof query>;
const mockScanQueueAdd = scanQueue.add as jest.MockedFunction<typeof scanQueue.add>;
const mockGetPresignedUrl = getPresignedUrl as jest.MockedFunction<typeof getPresignedUrl>;

describe('API Routes', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = Fastify({ logger: false });
    await server.register(healthRoutes);
    await server.register(orderRoutes);
    await server.ready();
  });

  afterEach(async () => {
    await server.close();
  });

  describe('GET /health', () => {
    it('should return ok with timestamp', async () => {
      const res = await server.inject({ method: 'GET', url: '/health' });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.status).toBe('ok');
      expect(body.timestamp).toBeDefined();
    });
  });

  describe('POST /api/orders', () => {
    it('should create order for valid domain and email', async () => {
      const now = new Date();
      // First call: customer upsert
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: 'cust-uuid-1234' }],
        command: 'INSERT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });
      // Second call: order insert
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: '550e8400-e29b-41d4-a716-446655440000', target_url: 'example.com', status: 'verification_pending', package: 'professional', verification_token: 'vectiscan-verify-mock12345678', created_at: now }],
        command: 'INSERT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com', email: 'test@example.com' },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.id).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(body.data.domain).toBe('example.com');
      expect(body.data.status).toBe('verification_pending');
      expect(body.data.package).toBe('professional');
      expect(body.data.verificationToken).toBe('vectiscan-verify-mock12345678');
      expect(mockScanQueueAdd).not.toHaveBeenCalled();
    });

    it('should reject invalid domain', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'http://example.com', email: 'test@example.com' },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error).toContain('Invalid domain');
    });

    it('should reject missing email', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().success).toBe(false);
      expect(res.json().error).toContain('email');
    });

    it('should reject invalid email', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com', email: 'not-an-email' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().success).toBe(false);
    });
  });

  describe('GET /api/orders/:id', () => {
    const orderId = '550e8400-e29b-41d4-a716-446655440000';

    it('should return order with progress', async () => {
      mockQuery
        .mockResolvedValueOnce({
          rows: [{
            id: orderId,
            target_url: 'example.com',
            status: 'scan_phase2',
            package: 'professional',
            customer_id: 'cust-uuid-1234',
            discovered_hosts: [{ ip: '1.2.3.4', fqdns: ['example.com'], status: 'scanning' }],
            hosts_total: 1,
            hosts_completed: 0,
            current_phase: 'phase2',
            current_tool: 'nikto',
            current_host: '1.2.3.4',
            scan_started_at: new Date('2026-03-12T14:30:05Z'),
            scan_finished_at: null,
            error_message: null,
            created_at: new Date('2026-03-12T14:30:00Z'),
          }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: [],
        })
        .mockResolvedValueOnce({
          rows: [],
          command: 'SELECT',
          rowCount: 0,
          oid: 0,
          fields: [],
        });

      const res = await server.inject({ method: 'GET', url: `/api/orders/${orderId}` });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.status).toBe('scan_phase2');
      expect(body.data.progress.currentTool).toBe('nikto');
      expect(body.data.hasReport).toBe(false);
      expect(body.data.customerId).toBe('cust-uuid-1234');
    });

    it('should return 404 for non-existent order', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({ method: 'GET', url: `/api/orders/${orderId}` });
      expect(res.statusCode).toBe(404);
      expect(res.json().success).toBe(false);
    });

    it('should return 400 for invalid UUID', async () => {
      const res = await server.inject({ method: 'GET', url: '/api/orders/not-a-uuid' });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /api/orders/:id/report', () => {
    const orderId = '550e8400-e29b-41d4-a716-446655440000';

    it('should stream PDF when report exists', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{
          minio_bucket: 'scan-reports',
          minio_path: `${orderId}.pdf`,
          file_size_bytes: 245760,
          created_at: new Date('2026-03-12T15:00:00Z'),
          target_url: 'example.com',
        }],
        command: 'SELECT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({ method: 'GET', url: `/api/orders/${orderId}/report` });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['content-disposition']).toContain('example.com');
    });

    it('should return 404 when no report exists', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({ method: 'GET', url: `/api/orders/${orderId}/report` });
      expect(res.statusCode).toBe(404);
      expect(res.json().error).toBe('Report not yet available');
    });
  });

  describe('Backwards compat redirects', () => {
    it('POST /api/scans should redirect to /api/orders', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com', email: 'test@example.com' },
      });
      expect(res.statusCode).toBe(307);
      expect(res.headers.location).toBe('/api/orders');
    });

    it('GET /api/scans/:id should redirect to /api/orders/:id', async () => {
      const id = '550e8400-e29b-41d4-a716-446655440000';
      const res = await server.inject({ method: 'GET', url: `/api/scans/${id}` });
      expect(res.statusCode).toBe(301);
      expect(res.headers.location).toBe(`/api/orders/${id}`);
    });

    it('GET /api/scans/:id/report should redirect to /api/orders/:id/report', async () => {
      const id = '550e8400-e29b-41d4-a716-446655440000';
      const res = await server.inject({ method: 'GET', url: `/api/scans/${id}/report` });
      expect(res.statusCode).toBe(301);
      expect(res.headers.location).toBe(`/api/orders/${id}/report`);
    });
  });
});
