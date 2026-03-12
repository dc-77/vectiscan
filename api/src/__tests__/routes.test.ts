import Fastify, { FastifyInstance } from 'fastify';
import { healthRoutes } from '../routes/health';
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

jest.mock('../lib/minio', () => ({
  minioClient: {},
  initBuckets: jest.fn(),
  getPresignedUrl: jest.fn(),
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
    await server.register(scanRoutes);
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

  describe('POST /api/scans', () => {
    it('should create scan for valid domain', async () => {
      const now = new Date();
      mockQuery.mockResolvedValueOnce({
        rows: [{ id: '550e8400-e29b-41d4-a716-446655440000', domain: 'example.com', status: 'created', created_at: now }],
        command: 'INSERT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });
      mockScanQueueAdd.mockResolvedValueOnce({} as never);

      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'example.com' },
      });

      expect(res.statusCode).toBe(201);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.id).toBe('550e8400-e29b-41d4-a716-446655440000');
      expect(body.data.domain).toBe('example.com');
      expect(body.data.status).toBe('created');
      expect(mockScanQueueAdd).toHaveBeenCalledWith('scan', {
        scanId: '550e8400-e29b-41d4-a716-446655440000',
        domain: 'example.com',
      });
    });

    it('should reject invalid domain', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: { domain: 'http://example.com' },
      });

      expect(res.statusCode).toBe(400);
      const body = res.json();
      expect(body.success).toBe(false);
      expect(body.error).toContain('Invalid domain');
    });

    it('should reject missing domain', async () => {
      const res = await server.inject({
        method: 'POST',
        url: '/api/scans',
        payload: {},
      });

      expect(res.statusCode).toBe(400);
      expect(res.json().success).toBe(false);
    });
  });

  describe('GET /api/scans/:id', () => {
    const scanId = '550e8400-e29b-41d4-a716-446655440000';

    it('should return scan with progress', async () => {
      mockQuery
        .mockResolvedValueOnce({
          rows: [{
            id: scanId,
            domain: 'example.com',
            status: 'scan_phase2',
            discovered_hosts: [{ ip: '1.2.3.4', fqdns: ['example.com'], status: 'scanning' }],
            hosts_total: 1,
            hosts_completed: 0,
            current_phase: 'phase2',
            current_tool: 'nikto',
            current_host: '1.2.3.4',
            started_at: new Date('2026-03-12T14:30:05Z'),
            finished_at: null,
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

      const res = await server.inject({ method: 'GET', url: `/api/scans/${scanId}` });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.status).toBe('scan_phase2');
      expect(body.data.progress.currentTool).toBe('nikto');
      expect(body.data.hasReport).toBe(false);
    });

    it('should return 404 for non-existent scan', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({ method: 'GET', url: `/api/scans/${scanId}` });
      expect(res.statusCode).toBe(404);
      expect(res.json().success).toBe(false);
    });

    it('should return 400 for invalid UUID', async () => {
      const res = await server.inject({ method: 'GET', url: '/api/scans/not-a-uuid' });
      expect(res.statusCode).toBe(400);
    });
  });

  describe('GET /api/scans/:id/report', () => {
    const scanId = '550e8400-e29b-41d4-a716-446655440000';

    it('should return presigned URL when report exists', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{
          minio_bucket: 'scan-reports',
          minio_path: `${scanId}.pdf`,
          file_size_bytes: 245760,
          created_at: new Date('2026-03-12T15:00:00Z'),
          domain: 'example.com',
        }],
        command: 'SELECT',
        rowCount: 1,
        oid: 0,
        fields: [],
      });
      mockGetPresignedUrl.mockResolvedValueOnce('http://minio:9000/scan-reports/test.pdf?signed=1');

      const res = await server.inject({ method: 'GET', url: `/api/scans/${scanId}/report` });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.success).toBe(true);
      expect(body.data.downloadUrl).toContain('minio');
      expect(body.data.fileName).toContain('example.com');
      expect(body.data.fileSize).toBe(245760);
    });

    it('should return 404 when no report exists', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: [],
      });

      const res = await server.inject({ method: 'GET', url: `/api/scans/${scanId}/report` });
      expect(res.statusCode).toBe(404);
      expect(res.json().error).toBe('Report not yet available');
    });
  });
});
