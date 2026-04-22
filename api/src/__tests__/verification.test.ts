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
  getProgressFromRedis: jest.fn().mockResolvedValue(null),
  enqueuePrecheck: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../lib/minio', () => ({
  minioClient: { getObject: jest.fn() },
  initBuckets: jest.fn(),
  getPresignedUrl: jest.fn(),
}));

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

jest.mock('../services/VerificationService', () => {
  const actual = jest.requireActual('../services/VerificationService');
  return {
    ...actual,
    generateToken: jest.fn().mockReturnValue('vectiscan-verify-mock12345678'),
    verifyAll: jest.fn(),
  };
});

jest.mock('../lib/audit', () => ({
  audit: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../lib/auth', () => ({
  hashPassword: jest.fn().mockResolvedValue('$2a$12$mockhash'),
  verifyPasswordHash: jest.fn().mockResolvedValue(true),
  generateJwt: jest.fn().mockReturnValue('mock-jwt-token'),
  verifyJwt: jest.fn().mockReturnValue({
    sub: 'user-uuid-1234',
    role: 'admin',
    customerId: 'cust-1',
    email: 'admin@test.com',
  }),
}));

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
    jest.resetAllMocks();
    // Re-set default mocks after resetAllMocks
    const { verifyJwt } = require('../lib/auth');
    (verifyJwt as jest.Mock).mockReturnValue({
      sub: 'user-uuid-1234',
      role: 'admin',
      customerId: 'cust-1',
      email: 'admin@test.com',
    });
    const { isValidDomain, isValidTarget, validateTargetBatch } = require('../lib/validate');
    (isValidDomain as jest.Mock).mockImplementation((d: string) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d));
    (isValidTarget as jest.Mock).mockImplementation((d: unknown) => {
      if (typeof d !== 'string') return null;
      if (/^[a-z]+:\/\//i.test(d)) return null;
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) return d.toLowerCase();
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$/.test(d)) return d;
      return null;
    });
    (validateTargetBatch as jest.Mock).mockImplementation((inputs: Array<{ raw_input?: unknown }>) => ({
      targets: inputs.map(i => ({
        raw_input: String(i?.raw_input ?? ''),
        valid: true,
        canonical: String(i?.raw_input ?? '').toLowerCase(),
        target_type: 'fqdn_root',
        policy_default: 'enumerate',
        warnings: [],
      })),
      errors: [],
    }));
    const { generateToken } = require('../services/VerificationService');
    (generateToken as jest.Mock).mockReturnValue('vectiscan-verify-mock12345678');
    server = Fastify({ logger: false });
    await server.register(orderRoutes);
    await server.register(verifyRoutes);
    await server.ready();
  });

  afterEach(async () => {
    await server.close();
  });

  const targetId = '650e8400-e29b-41d4-a716-446655440000';

  describe('POST /api/verify/check', () => {
    it('should return 400 for missing targetId', async () => {
      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: {} });
      expect(res.statusCode).toBe(400);
    });

    it('should return 404 for non-existent target', async () => {
      mockQuery.mockResolvedValueOnce(EMPTY_RESULT);
      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: { targetId } });
      expect(res.statusCode).toBe(404);
      expect(res.json().error).toBe('Target nicht gefunden');
    });

    it('should return 400 for IP/CIDR target', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: targetId, canonical: '85.22.47.32/27', target_type: 'cidr', order_id: orderId, subscription_id: null }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: { targetId } });
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe('verification_not_applicable_for_ip_targets');
    });

    it('should verify fqdn target and persist to verified_domains', async () => {
      // 1. SELECT scan_target
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: targetId, canonical: 'example.com', target_type: 'fqdn_root', order_id: orderId, subscription_id: null }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      mockVerifyAll.mockResolvedValueOnce({ verified: true, method: 'file' });
      // 2. SELECT customer_id (owner lookup)
      mockQuery.mockResolvedValueOnce({
        rows: [{ customer_id: 'cust-1' }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      // 3. INSERT INTO verified_domains
      mockQuery.mockResolvedValueOnce({ rows: [], command: 'INSERT', rowCount: 1, oid: 0, fields: [] });

      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: { targetId } });
      expect(res.json()).toEqual({ success: true, data: { verified: true, method: 'file' } });
      // Der Scan wird durch Admin-Review gestartet, nicht durch die Verifikation.
      expect(mockScanQueueAdd).not.toHaveBeenCalled();
    });

    it('should return verified:false without persistence on failure', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: targetId, canonical: 'example.com', target_type: 'fqdn_root', order_id: orderId, subscription_id: null }],
        command: 'SELECT', rowCount: 1, oid: 0, fields: [],
      });
      mockVerifyAll.mockResolvedValueOnce({ verified: false, method: null });

      const res = await server.inject({ method: 'POST', url: '/api/verify/check', payload: { targetId } });
      expect(res.json()).toEqual({ success: true, data: { verified: false, method: null } });
      // Nur der SELECT wurde durchgefuehrt, keine verified_domains-Persistenz.
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });
  });

  describe('GET /api/verify/status/:orderId', () => {
    it('should return 400 for invalid order ID', async () => {
      const res = await server.inject({ method: 'GET', url: '/api/verify/status/not-a-uuid' });
      expect(res.statusCode).toBe(400);
    });

    it('should return empty list when order has no FQDN targets', async () => {
      mockQuery.mockResolvedValueOnce(EMPTY_RESULT);
      const res = await server.inject({ method: 'GET', url: `/api/verify/status/${orderId}` });
      expect(res.statusCode).toBe(200);
      expect(res.json().data).toEqual({ targets: [] });
    });

    it('should list FQDN targets with cached verification status', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [
          { id: targetId, canonical: 'example.com', target_type: 'fqdn_root', verified: true, method: 'dns_txt' },
          { id: 'other-target', canonical: 'sub.example.com', target_type: 'fqdn_specific', verified: false, method: null },
        ],
        command: 'SELECT', rowCount: 2, oid: 0, fields: [],
      });
      const res = await server.inject({ method: 'GET', url: `/api/verify/status/${orderId}` });
      expect(res.json().data.targets).toHaveLength(2);
      expect(res.json().data.targets[0].verified).toBe(true);
      expect(res.json().data.targets[1].verified).toBe(false);
    });
  });

  describe('POST /api/orders (multi-target flow)', () => {
    const AUTH_HEADER = { authorization: 'Bearer mock-jwt-token' };

    it('should create order in precheck_running and return target stubs', async () => {
      // Order insert
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: orderId, status: 'precheck_running', package: 'perimeter', created_at: new Date() }],
        command: 'INSERT', rowCount: 1, oid: 0, fields: [],
      });
      // scan_targets insert
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: targetId }],
        command: 'INSERT', rowCount: 1, oid: 0, fields: [],
      });

      const res = await server.inject({
        method: 'POST',
        url: '/api/orders',
        headers: AUTH_HEADER,
        payload: { package: 'perimeter', targets: [{ raw_input: 'example.com' }] },
      });
      const body = res.json();

      expect(res.statusCode).toBe(201);
      expect(body.data.status).toBe('precheck_running');
      expect(body.data.targetCount).toBe(1);
      expect(body.data.targets[0].id).toBe(targetId);
      expect(body.data.targets[0].canonical).toBe('example.com');
      // Multi-Target-Orders queuen den Scan nicht direkt — der laeuft ueber Admin-Release.
      expect(mockScanQueueAdd).not.toHaveBeenCalled();
    });
  });
});
