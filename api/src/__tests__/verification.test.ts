import Fastify, { FastifyInstance } from 'fastify';
import { orderRoutes } from '../routes/orders';
import { verifyRoutes } from '../routes/verify';

// ──────────────────────────────────────────────
// Mocks
// ──────────────────────────────────────────────

jest.mock('dns/promises', () => ({
  resolveTxt: jest.fn(),
}));

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

jest.mock('../lib/minio', () => ({
  minioClient: { getObject: jest.fn() },
  initBuckets: jest.fn(),
  getPresignedUrl: jest.fn(),
}));

jest.mock('../lib/validate', () => ({
  isValidDomain: jest.fn((d: string) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d)),
}));

jest.mock('../services/VerificationService', () => {
  const actual = jest.requireActual('../services/VerificationService');
  return {
    ...actual,
    generateToken: jest.fn().mockReturnValue('vectiscan-verify-mock12345678'),
    verifyAll: jest.fn(),
  };
});

import dns from 'dns/promises';
import { query } from '../lib/db';
import { scanQueue } from '../lib/queue';

const actualService = jest.requireActual('../services/VerificationService') as typeof import('../services/VerificationService');
const realGenerateToken = actualService.generateToken;
const realVerifyDnsTxt = actualService.verifyDnsTxt;
const realVerifyFile = actualService.verifyFile;
const realVerifyMetaTag = actualService.verifyMetaTag;
const realVerifyAll = actualService.verifyAll;

const mockResolveTxt = dns.resolveTxt as jest.MockedFunction<typeof dns.resolveTxt>;
const mockQuery = query as jest.MockedFunction<typeof query>;
const mockScanQueueAdd = scanQueue.add as jest.MockedFunction<typeof scanQueue.add>;

const mockFetch = jest.fn() as jest.MockedFunction<typeof global.fetch>;
global.fetch = mockFetch;

const { verifyAll: mockVerifyAll } = jest.requireMock('../services/VerificationService') as { verifyAll: jest.Mock };

// ──────────────────────────────────────────────
// VerificationService — Unit Tests
// ──────────────────────────────────────────────

describe('VerificationService', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('generateToken', () => {
    it('should start with vectiscan-verify-', () => {
      expect(realGenerateToken().startsWith('vectiscan-verify-')).toBe(true);
    });

    it('should have length 29 (17 prefix + 12 UUID chars)', () => {
      expect(realGenerateToken().length).toBe(29);
    });

    it('should generate unique tokens', () => {
      const tokens = new Set(Array.from({ length: 20 }, () => realGenerateToken()));
      expect(tokens.size).toBe(20);
    });
  });

  describe('verifyDnsTxt', () => {
    const token = 'vectiscan-verify-abc123def456';

    it('should return verified:true when TXT record contains the token', async () => {
      mockResolveTxt.mockResolvedValueOnce([[token]]);
      const result = await realVerifyDnsTxt('example.com', token);
      expect(result).toEqual({ verified: true, method: 'dns_txt' });
      expect(mockResolveTxt).toHaveBeenCalledWith('_vectiscan-verify.example.com');
    });

    it('should return verified:false when TXT record does not match', async () => {
      mockResolveTxt.mockResolvedValueOnce([['wrong-token']]);
      const result = await realVerifyDnsTxt('example.com', token);
      expect(result).toEqual({ verified: false, method: 'dns_txt' });
    });

    it('should return verified:false on DNS error', async () => {
      mockResolveTxt.mockRejectedValueOnce(new Error('ENOTFOUND'));
      const result = await realVerifyDnsTxt('example.com', token);
      expect(result).toEqual({ verified: false, method: 'dns_txt' });
    });

    it('should find token among multiple TXT records', async () => {
      mockResolveTxt.mockResolvedValueOnce([['other'], [token], ['another']]);
      const result = await realVerifyDnsTxt('example.com', token);
      expect(result).toEqual({ verified: true, method: 'dns_txt' });
    });
  });

  describe('verifyFile', () => {
    const token = 'vectiscan-verify-abc123def456';

    it('should return verified:true when file contains the token', async () => {
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve(token) } as Response);
      const result = await realVerifyFile('example.com', token);
      expect(result).toEqual({ verified: true, method: 'file' });
      expect(mockFetch).toHaveBeenCalledWith(
        'https://example.com/.well-known/vectiscan-verify.txt',
        expect.objectContaining({ signal: expect.any(AbortSignal) }),
      );
    });

    it('should handle whitespace around token', async () => {
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve(`  ${token}  \n`) } as Response);
      const result = await realVerifyFile('example.com', token);
      expect(result).toEqual({ verified: true, method: 'file' });
    });

    it('should return verified:false when content does not match', async () => {
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve('wrong') } as Response);
      const result = await realVerifyFile('example.com', token);
      expect(result).toEqual({ verified: false, method: 'file' });
    });

    it('should return verified:false on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('AbortError'));
      const result = await realVerifyFile('example.com', token);
      expect(result).toEqual({ verified: false, method: 'file' });
    });
  });

  describe('verifyMetaTag', () => {
    const token = 'vectiscan-verify-abc123def456';

    it('should return verified:true with double quotes', async () => {
      const html = `<html><head><meta name="vectiscan-verify" content="${token}"></head></html>`;
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve(html) } as Response);
      const result = await realVerifyMetaTag('example.com', token);
      expect(result).toEqual({ verified: true, method: 'meta_tag' });
    });

    it('should return verified:true with single quotes', async () => {
      const html = `<html><head><meta name='vectiscan-verify' content='${token}'></head></html>`;
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve(html) } as Response);
      const result = await realVerifyMetaTag('example.com', token);
      expect(result).toEqual({ verified: true, method: 'meta_tag' });
    });

    it('should return verified:false when meta tag missing', async () => {
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve('<html></html>') } as Response);
      const result = await realVerifyMetaTag('example.com', token);
      expect(result).toEqual({ verified: false, method: 'meta_tag' });
    });

    it('should return verified:false when content wrong', async () => {
      const html = '<meta name="vectiscan-verify" content="wrong-token">';
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve(html) } as Response);
      const result = await realVerifyMetaTag('example.com', token);
      expect(result).toEqual({ verified: false, method: 'meta_tag' });
    });

    it('should return verified:false on fetch error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Timeout'));
      const result = await realVerifyMetaTag('example.com', token);
      expect(result).toEqual({ verified: false, method: 'meta_tag' });
    });
  });

  describe('verifyAll', () => {
    const token = 'vectiscan-verify-abc123def456';

    it('should return first successful result', async () => {
      mockResolveTxt.mockResolvedValueOnce([[token]]);
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve('wrong') } as Response);
      mockFetch.mockResolvedValueOnce({ text: () => Promise.resolve('<html></html>') } as Response);
      const result = await realVerifyAll('example.com', token);
      expect(result.verified).toBe(true);
    });

    it('should return { verified: false, method: null } when all fail', async () => {
      mockResolveTxt.mockRejectedValueOnce(new Error('ENOTFOUND'));
      mockFetch.mockRejectedValueOnce(new Error('error'));
      mockFetch.mockRejectedValueOnce(new Error('error'));
      const result = await realVerifyAll('example.com', token);
      expect(result).toEqual({ verified: false, method: null });
    });
  });
});

// ──────────────────────────────────────────────
// Verification API Endpoints
// ──────────────────────────────────────────────

const EMPTY_RESULT = { rows: [], command: 'SELECT' as const, rowCount: 0, oid: 0, fields: [] };
const orderId = '550e8400-e29b-41d4-a716-446655440000';

describe('Verification API', () => {
  let server: FastifyInstance;

  beforeEach(async () => {
    jest.clearAllMocks();
    server = Fastify({ logger: false });
    await server.register(orderRoutes);
    await server.register(verifyRoutes);
    await server.ready();
  });

  afterEach(async () => {
    await server.close();
  });

  describe('POST /api/verify/check', () => {
    it('should return 404 for non-existent order', async () => {
      mockQuery.mockResolvedValueOnce(EMPTY_RESULT);
      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: { orderId } });
      expect(res.statusCode).toBe(404);
      expect(res.json().error).toBe('Order nicht gefunden');
    });

    it('should return verified:true idempotently for already-verified order', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, target_url: 'example.com', verification_token: 'tok', status: 'verified', verified_at: new Date(), verification_method: 'dns_txt' }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: { orderId } });
      expect(res.json()).toEqual({ success: true, data: { verified: true, method: 'dns_txt' } });
      expect(mockVerifyAll).not.toHaveBeenCalled();
    });

    it('should verify and update order on success', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, target_url: 'example.com', verification_token: 'tok', status: 'verification_pending', verified_at: null, verification_method: null }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      mockVerifyAll.mockResolvedValueOnce({ verified: true, method: 'file' });
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'UPDATE', rowCount: 1, oid: 0, fields: [] });
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'INSERT', rowCount: 1, oid: 0, fields: [] });

      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: { orderId } });
      expect(res.json()).toEqual({ success: true, data: { verified: true, method: 'file' } });

      // Verify UPDATE was called
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("status = 'verified'"),
        ['file', orderId],
      );
      // Verify audit_log INSERT
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('audit_log'),
        [orderId, 'verification_success', expect.stringContaining('"method":"file"'), expect.any(String)],
      );
    });

    it('should return verified:false without DB update on failure', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, target_url: 'example.com', verification_token: 'tok', status: 'verification_pending', verified_at: null, verification_method: null }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      mockVerifyAll.mockResolvedValueOnce({ verified: false, method: null });

      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: { orderId } });
      expect(res.json()).toEqual({ success: true, data: { verified: false } });
      expect(mockQuery).toHaveBeenCalledTimes(1); // Only SELECT, no UPDATE
    });

    it('should return 400 for missing orderId', async () => {
      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: {} });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /api/verify/status/:orderId', () => {
    it('should return 404 for non-existent order', async () => {
      mockQuery.mockResolvedValueOnce(EMPTY_RESULT);
      const res = await server.inject({ method: 'GET', url: `/api/verify/status/${orderId}` });
      expect(res.statusCode).toBe(404);
    });

    it('should return unverified status with token', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ target_url: 'example.com', verification_token: 'vectiscan-verify-abc123', verification_method: null, verified_at: null }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      const res = await server.inject({ method: 'GET', url: `/api/verify/status/${orderId}` });
      expect(res.json().data).toEqual({ verified: false, method: null, token: 'vectiscan-verify-abc123', domain: 'example.com' });
    });

    it('should return verified status with method', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ target_url: 'example.com', verification_token: 'tok', verification_method: 'dns_txt', verified_at: new Date() }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      const res = await server.inject({ method: 'GET', url: `/api/verify/status/${orderId}` });
      expect(res.json().data.verified).toBe(true);
      expect(res.json().data.method).toBe('dns_txt');
    });
  });

  describe('POST /api/orders (verification flow)', () => {
    it('should return verificationToken and instructions', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [{ id: 'cust-1' }], command: 'INSERT', rowCount: 1, oid: 0, fields: [] });
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, target_url: 'example.com', status: 'verification_pending', package: 'professional', verification_token: 'vectiscan-verify-mock12345678', created_at: new Date() }],
        command: 'INSERT', rowCount: 1, oid: 0, fields: [],
      });

      const res = await server.inject({ method: 'POST', url: '/api/orders', payload: { domain: 'example.com', email: 'test@example.com' } });
      const body = res.json();

      expect(res.statusCode).toBe(201);
      expect(body.data.status).toBe('verification_pending');
      expect(body.data.verificationToken).toBe('vectiscan-verify-mock12345678');
      expect(body.data.verificationInstructions.dns_txt).toContain('_vectiscan-verify.example.com');
      expect(body.data.verificationInstructions.file).toContain('.well-known/vectiscan-verify.txt');
      expect(body.data.verificationInstructions.meta_tag).toContain('vectiscan-verify');
    });

    it('should NOT queue a scan job', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [{ id: 'cust-1' }], command: 'INSERT', rowCount: 1, oid: 0, fields: [] });
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, target_url: 'example.com', status: 'verification_pending', package: 'professional', verification_token: 'tok', created_at: new Date() }],
        command: 'INSERT', rowCount: 1, oid: 0, fields: [],
      });

      await server.inject({ method: 'POST', url: '/api/orders', payload: { domain: 'example.com', email: 'test@example.com' } });
      expect(mockScanQueueAdd).not.toHaveBeenCalled();
    });
  });
});
