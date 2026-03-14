import { FastifyInstance } from 'fastify';
import { query } from '../lib/db.js';
import { scanQueue, publishEvent } from '../lib/queue.js';
import { minioClient } from '../lib/minio.js';
import { isValidDomain } from '../lib/validate.js';

const VALID_PACKAGES = ['basic', 'professional', 'nis2'] as const;
type ScanPackage = typeof VALID_PACKAGES[number];

const ESTIMATED_DURATIONS: Record<ScanPackage, string> = {
  basic: '~10 Minuten',
  professional: '~45 Minuten',
  nis2: '~45 Minuten',
};

interface CreateScanBody {
  domain: string;
  package?: string;
}

interface ScanParams {
  id: string;
}

export async function scanRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/scans
  server.post<{ Body: CreateScanBody }>('/api/scans', async (request, reply) => {
    const { domain } = request.body || {};
    const pkg = (request.body?.package || 'professional') as string;

    if (!isValidDomain(domain)) {
      return reply.status(400).send({
        success: false,
        error: 'Invalid domain. Provide a valid FQDN without protocol, path, or port.',
      });
    }

    if (!VALID_PACKAGES.includes(pkg as ScanPackage)) {
      return reply.status(400).send({
        success: false,
        error: 'Invalid package. Must be basic, professional, or nis2.',
      });
    }

    const result = await query<{ id: string; domain: string; status: string; package: string; created_at: Date }>(
      'INSERT INTO scans (domain, package) VALUES ($1, $2) RETURNING id, domain, status, package, created_at',
      [domain, pkg],
    );

    const scan = result.rows[0];

    await scanQueue.add('scan', { scanId: scan.id, targetDomain: scan.domain, package: scan.package });

    return reply.status(201).send({
      success: true,
      data: {
        id: scan.id,
        domain: scan.domain,
        status: scan.status,
        package: scan.package,
        createdAt: scan.created_at.toISOString(),
      },
    });
  });

  // GET /api/scans/:id
  server.get<{ Params: ScanParams }>('/api/scans/:id', async (request, reply) => {
    const { id } = request.params;

    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid scan ID format' });
    }

    const result = await query(
      `SELECT id, domain, status, package, discovered_hosts, hosts_total, hosts_completed,
              current_phase, current_tool, current_host,
              started_at, finished_at, error_message, created_at
       FROM scans WHERE id = $1`,
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Scan not found' });
    }

    const scan = result.rows[0] as Record<string, unknown>;

    // Check if report exists
    const reportResult = await query('SELECT id FROM reports WHERE scan_id = $1', [id]);
    const hasReport = reportResult.rows.length > 0;

    const scanPackage = (scan.package || 'professional') as ScanPackage;

    return {
      success: true,
      data: {
        id: scan.id,
        domain: scan.domain,
        status: scan.status,
        package: scanPackage,
        estimatedDuration: ESTIMATED_DURATIONS[scanPackage],
        progress: {
          phase: scan.current_phase || null,
          currentTool: scan.current_tool || null,
          currentHost: scan.current_host || null,
          hostsTotal: scan.hosts_total || 0,
          hostsCompleted: scan.hosts_completed || 0,
          discoveredHosts: scan.discovered_hosts || [],
        },
        startedAt: scan.started_at ? (scan.started_at as Date).toISOString() : null,
        finishedAt: scan.finished_at ? (scan.finished_at as Date).toISOString() : null,
        error: scan.error_message || null,
        hasReport,
      },
    };
  });

  // GET /api/scans/:id/report
  server.get<{ Params: ScanParams }>('/api/scans/:id/report', async (request, reply) => {
    const { id } = request.params;

    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid scan ID format' });
    }

    const result = await query(
      `SELECT r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, s.domain
       FROM reports r JOIN scans s ON r.scan_id = s.id
       WHERE r.scan_id = $1`,
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Report not yet available' });
    }

    const report = result.rows[0] as Record<string, unknown>;
    const bucket = report.minio_bucket as string;
    const path = report.minio_path as string;
    const domain = report.domain as string;
    const fileSize = report.file_size_bytes as number;
    const createdAt = report.created_at as Date;

    const dateStr = createdAt.toISOString().split('T')[0];
    const fileName = `vectiscan-${domain}-${dateStr}.pdf`;

    const stream = await minioClient.getObject(bucket, path);

    return reply
      .header('Content-Type', 'application/pdf')
      .header('Content-Disposition', `attachment; filename="${fileName}"`)
      .header('Content-Length', fileSize)
      .send(stream);
  });

  // DELETE /api/scans/:id — Cancel a running scan
  server.delete<{ Params: ScanParams }>('/api/scans/:id', async (request, reply) => {
    const { id } = request.params;

    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid scan ID format' });
    }

    const result = await query(
      'SELECT id, status FROM scans WHERE id = $1',
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Scan not found' });
    }

    const scan = result.rows[0] as Record<string, unknown>;
    const status = scan.status as string;

    // Only cancel scans that are still running
    const cancellableStatuses = ['created', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_complete', 'report_generating'];
    if (!cancellableStatuses.includes(status)) {
      return reply.status(409).send({
        success: false,
        error: `Scan cannot be cancelled in status: ${status}`,
      });
    }

    await query(
      "UPDATE scans SET status = 'cancelled', error_message = 'Vom Benutzer abgebrochen', finished_at = NOW(), updated_at = NOW() WHERE id = $1",
      [id],
    );

    // Notify via Redis Pub/Sub so WebSocket clients get the update
    await publishEvent(id, {
      type: 'status',
      scanId: id,
      status: 'cancelled',
      error: 'Vom Benutzer abgebrochen',
    });

    return { success: true, data: null };
  });
}
