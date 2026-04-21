import Fastify, { FastifyInstance } from 'fastify';
import { healthRoutes } from '../routes/health';
import { orderRoutes } from '../routes/orders';
import { authRoutes } from '../routes/auth';

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
      removeObject: jest.fn().mockResolvedValue(undefined),
    },
    initBuckets: jest.fn(),
    getPresignedUrl: jest.fn(),
  };
});

// Use a stable implementation that survives jest.resetAllMocks()
const _isValidTarget = (d: unknown) => {
  if (typeof d !== 'string') return null;
  if (/^[a-z]+:\/\//i.test(d)) return null;
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) return d.toLowerCase();
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$/.test(d)) return d;
  return null;
};
jest.mock('../lib/validate', () => ({
  isValidDomain: jest.fn((d: string) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)),
  isValidTarget: jest.fn((d: unknown) => _isValidTarget(d)),
}));

jest.mock('../services/VerificationService', () => ({
  generateToken: jest.fn().mockReturnValue('vectiscan-verify-mock12345678'),
  verifyAll: jest.fn(),
}));

// Mock auth — generate real-ish JWTs for testing
jest.mock('../lib/auth', () => ({
  hashPassword: jest.fn().mockResolvedValue('$2a$12$mockhash'),
  verifyPasswordHash: jest.fn().mockResolvedValue(true),
  generateJwt: jest.fn().mockReturnValue('mock-jwt-token'),
  verifyJwt: jest.fn().mockReturnValue({
    sub: 'user-uuid-1234',
    role: 'admin',
    customerId: 'cust-uuid-1234',
    email: 'admin@test.com',
  }),
}));

jest.mock('../lib/audit', () => ({
  audit: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../lib/email', () => ({
  sendScanCompleteEmail: jest.fn().mockResolvedValue(undefined),
  sendPasswordResetEmail: jest.fn().mockResolvedValue(undefined),
}));

import { query } from '../lib/db';
import { scanQueue } from '../lib/queue';
import { getPresignedUrl } from '../lib/minio';
import { minioClient } from '../lib/minio';
import { verifyJwt } from '../lib/auth';
import { publishEvent } from '../lib/queue';

const mockQuery = query as jest.MockedFunction<typeof query>;
const mockScanQueueAdd = scanQueue.add as jest.MockedFunction<typeof scanQueue.add>;
const mockGetPresignedUrl = getPresignedUrl as jest.MockedFunction<typeof getPresignedUrl>;
const mockVerifyJwt = verifyJwt as jest.MockedFunction<typeof verifyJwt>;
const mockMinioRemoveObject = minioClient.removeObject as jest.MockedFunction<typeof minioClient.removeObject>;
const mockPublishEvent = publishEvent as jest.MockedFunction<typeof publishEvent>;

const AUTH_HEADER = { authorization: 'Bearer mock-jwt-token' };

describe('API Routes', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    // Re-set default mocks after resetAllMocks
    mockVerifyJwt.mockReturnValue({
      sub: 'user-uuid-1234',
      role: 'admin',
      customerId: 'cust-uuid-1234',
      email: 'admin@test.com',
    } as ReturnType<typeof verifyJwt>);
    mockMinioRemoveObject.mockResolvedValue(undefined as never);
    mockPublishEvent.mockResolvedValue(undefined as never);
    const { Readable } = require('stream');
    (minioClient.getObject as jest.Mock).mockResolvedValue(Readable.from(Buffer.from('fake-pdf-content')));
    const { isValidDomain } = require('../lib/validate');
    (isValidDomain as jest.Mock).mockImplementation((d: string) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d));
    const { generateToken } = require('../services/VerificationService');
    (generateToken as jest.Mock).mockReturnValue('vectiscan-verify-mock12345678');
    const { hashPassword, generateJwt } = require('../lib/auth');
    (hashPassword as jest.Mock).mockResolvedValue('$2a$12$mockhash');
    (generateJwt as jest.Mock).mockReturnValue('mock-jwt-token');
    server = Fastify({ logger: false });
    await server.register(healthRoutes);
    await server.register(orderRoutes);
    await server.register(authRoutes);
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
    it('should return 401 without auth', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        payload: { domain: 'example.com' },
      });
      expect(res.statusCode).toBe(401);
    });

    it('should create order for valid domain with auth', async () => {
      const now = new Date();
      // 1: verified_domains check (no existing verification)
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      // 2: subscription auto-link lookup (no matching active subscription)
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      // 3: order insert
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: '550e8400-e29b-41d4-a716-446655440000', target_url: 'example.com', status: 'verification_pending', package: 'professional', verification_token: 'vectiscan-verify-mock12345678', created_at: now, subscription_id: null }],
        command: 'INSERT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        headers: AUTH_HEADER,
        payload: { domain: 'example.com' },
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
        headers: AUTH_HEADER,
        payload: { domain: 'http://example.com' },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error).toContain('Invalid domain');
    });
  });

  describe('GET /api/orders', () => {
    it('should return 401 without auth', async () => {
      const res = await server.inject({ method: 'GET', url: '/api/orders' });
      expect(res.statusCode).toBe(401);
    });

    it('should return orders for authenticated user', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{
          id: '550e8400-e29b-41d4-a716-446655440000',
          target_url: 'example.com',
          email: 'admin@test.com',
          package: 'professional',
          status: 'report_complete',
          error_message: null,
          scan_started_at: new Date(),
          scan_finished_at: new Date(),
          created_at: new Date(),
          has_report: true,
        }],
        command: 'SELECT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({
        method: 'GET',
        url: '/api/orders',
        headers: AUTH_HEADER,
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.orders).toHaveLength(1);
    });

    it('should filter by customer_id for non-admin users', async () => {
      mockVerifyJwt.mockReturnValue({
        sub: 'user-uuid-5678',
        role: 'customer',
        customerId: 'cust-uuid-5678',
        email: 'customer@test.com',
      } as ReturnType<typeof verifyJwt>);

      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({
        method: 'GET',
        url: '/api/orders',
        headers: AUTH_HEADER,
      });

      expect(res.statusCode).toBe(200);
      // Verify the query was called with customer_id filter
      const queryCall = mockQuery.mock.calls[0];
      expect(queryCall[0]).toContain('WHERE o.customer_id = $1');
      expect(queryCall[1]).toEqual(['cust-uuid-5678']);
    });
  });

  describe('GET /api/orders/:id', () => {
    const orderId = '550e8400-e29b-41d4-a716-446655440000';

    it('should return order with progress for admin', async () => {
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

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}`,
        headers: AUTH_HEADER,
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.status).toBe('scan_phase2');
      expect(body.data.progress.currentTool).toBe('nikto');
      expect(body.data.hasReport).toBe(false);
    });

    it('should return 403 for customer accessing another users order', async () => {
      mockVerifyJwt.mockReturnValue({
        sub: 'user-uuid-5678',
        role: 'customer',
        customerId: 'cust-uuid-OTHER',
        email: 'other@test.com',
      } as ReturnType<typeof verifyJwt>);

      mockQuery.mockResolvedValueOnce({
        rows: [{
          id: orderId,
          target_url: 'example.com',
          status: 'scanning',
          package: 'professional',
          customer_id: 'cust-uuid-1234',
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
        command: 'SELECT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}`,
        headers: AUTH_HEADER,
      });
      expect(res.statusCode).toBe(403);
    });

    it('should return 404 for non-existent order', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}`,
        headers: AUTH_HEADER,
      });
      expect(res.statusCode).toBe(404);
      expect(res.json().success).toBe(false);
    });

    it('should return 400 for invalid UUID', async () => {
      const res = await server.inject({
        method: 'GET',
        url: '/api/orders/not-a-uuid',
        headers: AUTH_HEADER,
      });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /api/orders/:id/report', () => {
    const orderId = '550e8400-e29b-41d4-a716-446655440000';

    it('should stream PDF when report exists', async () => {
      // First: ownership check
      mockQuery.mockResolvedValueOnce({
        rows: [{ customer_id: 'cust-uuid-1234' }],
        command: 'SELECT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });
      // Second: report query
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

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}/report`,
        headers: AUTH_HEADER,
      });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['content-disposition']).toContain('example.com');
    });

    it('should accept token as query parameter', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ customer_id: 'cust-uuid-1234' }],
        command: 'SELECT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });
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

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}/report?token=mock-jwt-token`,
      });
      expect(res.statusCode).toBe(200);
    });

    it('should return 404 when no report exists', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ customer_id: 'cust-uuid-1234' }],
        command: 'SELECT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}/report`,
        headers: AUTH_HEADER,
      });
      expect(res.statusCode).toBe(404);
      expect(res.json().error).toBe('Report not yet available');
    });
  });

  describe('DELETE /api/orders/:id — admin permanent delete', () => {
    const orderId = '550e8400-e29b-41d4-a716-446655440000';

    it('should permanently delete order for admin', async () => {
      // Order lookup
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, status: 'report_complete', customer_id: 'cust-uuid-1234' }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      // audit_log delete
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'DELETE', rowCount: 0, oid: 0, fields: [] });
      // order delete
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'DELETE', rowCount: 1, oid: 0, fields: [] });

      const res = await server.inject({
        method: 'DELETE',
        url: `/api/orders/${orderId}?permanent=true`,
        headers: AUTH_HEADER,
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().success).toBe(true);
      expect(mockMinioRemoveObject).toHaveBeenCalledTimes(2);
    });

    it('should deny permanent delete for customer', async () => {
      mockVerifyJwt.mockReturnValue({
        sub: 'user-uuid-5678',
        role: 'customer',
        customerId: 'cust-uuid-1234',
        email: 'customer@test.com',
      } as ReturnType<typeof verifyJwt>);

      // Order lookup
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, status: 'report_complete', customer_id: 'cust-uuid-1234' }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });

      const res = await server.inject({
        method: 'DELETE',
        url: `/api/orders/${orderId}?permanent=true`,
        headers: AUTH_HEADER,
      });

      expect(res.statusCode).toBe(403);
    });

    it('should soft-cancel order without permanent flag', async () => {
      // Order lookup
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, status: 'scanning', customer_id: 'cust-uuid-1234' }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      // Update status
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'UPDATE', rowCount: 1, oid: 0, fields: [] });

      const res = await server.inject({
        method: 'DELETE',
        url: `/api/orders/${orderId}`,
        headers: AUTH_HEADER,
      });

      expect(res.statusCode).toBe(200);
      expect(mockMinioRemoveObject).not.toHaveBeenCalled();
    });
  });

  describe('GET /api/orders/:id/report — download_token auth', () => {
    const orderId = '550e8400-e29b-41d4-a716-446655440000';

    it('should allow download via download_token', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{
          minio_bucket: 'scan-reports',
          minio_path: `${orderId}.pdf`,
          file_size_bytes: 1024,
          created_at: new Date('2026-03-12T15:00:00Z'),
          expires_at: new Date('2027-01-01T00:00:00Z'),
          target_url: 'example.com',
        }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      // download_count update
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'UPDATE', rowCount: 1, oid: 0, fields: [] });

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}/report?download_token=valid-token-123`,
      });

      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
    });

    it('should reject invalid download_token', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT', rowCount: 0, oid: 0, fields: [],
      });

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}/report?download_token=bad-token`,
      });

      expect(res.statusCode).toBe(403);
    });

    it('should reject expired download_token', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{
          minio_bucket: 'scan-reports',
          minio_path: `${orderId}.pdf`,
          file_size_bytes: 1024,
          created_at: new Date('2026-03-12T15:00:00Z'),
          expires_at: new Date('2025-01-01T00:00:00Z'), // expired
          target_url: 'example.com',
        }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });

      const res = await server.inject({
        method: 'GET',
        url: `/api/orders/${orderId}/report?download_token=expired-token`,
      });

      expect(res.statusCode).toBe(410);
    });
  });

  describe('POST /api/auth/forgot-password', () => {
    it('should return 200 even for non-existent email', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT', rowCount: 0, oid: 0, fields: [],
      });

      const res = await server.inject({
        method: 'POST',
        url: '/api/auth/forgot-password',
        payload: { email: 'nobody@test.com' },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().success).toBe(true);
    });

    it('should return 400 for invalid email', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/auth/forgot-password',
        payload: { email: 'invalid' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  describe('POST /api/auth/reset-password', () => {
    it('should reset password with valid token', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{
          id: 'user-uuid-1234',
          email: 'user@test.com',
          role: 'customer',
          customer_id: 'cust-uuid-1234',
          reset_token_expires_at: new Date(Date.now() + 3600000),
        }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      // Password update
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'UPDATE', rowCount: 1, oid: 0, fields: [] });

      const res = await server.inject({
        method: 'POST',
        url: '/api/auth/reset-password',
        payload: { token: 'valid-reset-token', password: 'newpassword123' },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json().success).toBe(true);
      expect(res.json().data.token).toBeDefined();
    });

    it('should reject invalid token', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT', rowCount: 0, oid: 0, fields: [],
      });

      const res = await server.inject({
        method: 'POST',
        url: '/api/auth/reset-password',
        payload: { token: 'bad-token', password: 'newpassword123' },
      });

      expect(res.statusCode).toBe(400);
    });

    it('should reject short password', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/auth/reset-password',
        payload: { token: 'some-token', password: 'short' },
      });

      expect(res.statusCode).toBe(400);
    });
  });

  describe('Backwards compat redirects', () => {
    it('POST /api/scans should redirect to /api/orders', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com' },
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
