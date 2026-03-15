import { FastifyInstance } from 'fastify';
import { query } from '../lib/db.js';
import { scanQueue, publishEvent, getProgressFromRedis } from '../lib/queue.js';
import { minioClient } from '../lib/minio.js';
import { isValidDomain } from '../lib/validate.js';
import { generateToken } from '../services/VerificationService.js';

const VALID_PACKAGES = ['basic', 'professional', 'nis2'] as const;
type ScanPackage = typeof VALID_PACKAGES[number];

const ESTIMATED_DURATIONS: Record<ScanPackage, string> = {
  basic: '~10 Minuten',
  professional: '~45 Minuten',
  nis2: '~45 Minuten',
};

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

interface CreateOrderBody {
  email: string;
  domain: string;
  package?: string;
}

interface OrderParams {
  id: string;
}

export async function orderRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/orders
  server.post<{ Body: CreateOrderBody }>('/api/orders', async (request, reply) => {
    const { domain, email } = request.body || {};
    const pkg = (request.body?.package || 'professional') as string;

    if (!email || !EMAIL_REGEX.test(email)) {
      return reply.status(400).send({
        success: false,
        error: 'Invalid or missing email address.',
      });
    }

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

    // Find or create customer
    const customerResult = await query<{ id: string }>(
      'INSERT INTO customers (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id',
      [email],
    );
    const customerId = customerResult.rows[0].id;

    // Insert order with verification token
    const verificationToken = generateToken();
    const result = await query<{ id: string; target_url: string; status: string; package: string; verification_token: string; created_at: Date }>(
      "INSERT INTO orders (customer_id, target_url, package, verification_token, status) VALUES ($1, $2, $3, $4, 'verification_pending') RETURNING id, target_url, status, package, verification_token, created_at",
      [customerId, domain, pkg, verificationToken],
    );

    const order = result.rows[0];

    return reply.status(201).send({
      success: true,
      data: {
        id: order.id,
        domain: order.target_url,
        status: order.status,
        package: order.package,
        verificationToken: order.verification_token,
        verificationInstructions: {
          dns_txt: `Create a TXT record at _vectiscan-verify.${domain} with value: ${order.verification_token}`,
          file: `Place a file at https://${domain}/.well-known/vectiscan-verify.txt containing: ${order.verification_token}`,
          meta_tag: `Add <meta name="vectiscan-verify" content="${order.verification_token}"> to your homepage`,
        },
      },
    });
  });

  // GET /api/orders — list all orders
  server.get('/api/orders', async (_request, _reply) => {
    const result = await query(
      `SELECT o.id, o.target_url, o.package, o.status, o.error_message,
              o.scan_started_at, o.scan_finished_at, o.created_at,
              c.email,
              EXISTS(SELECT 1 FROM reports r WHERE r.order_id = o.id) AS has_report
       FROM orders o
       JOIN customers c ON o.customer_id = c.id
       ORDER BY o.created_at DESC`,
    );

    const orders = result.rows.map((row: Record<string, unknown>) => ({
      id: row.id,
      domain: row.target_url,
      email: row.email,
      package: row.package,
      status: row.status,
      hasReport: row.has_report === true || row.has_report === 't',
      error: row.error_message || null,
      startedAt: row.scan_started_at ? (row.scan_started_at as Date).toISOString() : null,
      finishedAt: row.scan_finished_at ? (row.scan_finished_at as Date).toISOString() : null,
      createdAt: (row.created_at as Date).toISOString(),
    }));

    return { success: true, data: { orders } };
  });

  // POST /api/scans — backwards compat redirect
  server.post('/api/scans', async (_request, reply) => {
    return reply.redirect('/api/orders', 307);
  });

  // GET /api/orders/:id
  server.get<{ Params: OrderParams }>('/api/orders/:id', async (request, reply) => {
    const { id } = request.params;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    const result = await query(
      `SELECT o.id, o.target_url, o.status, o.package, o.customer_id,
              o.discovered_hosts, o.hosts_total, o.hosts_completed,
              o.current_phase, o.current_tool, o.current_host,
              o.scan_started_at, o.scan_finished_at, o.error_message, o.created_at
       FROM orders o WHERE o.id = $1`,
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }

    const order = result.rows[0] as Record<string, unknown>;

    // Check if report exists
    const reportResult = await query('SELECT id FROM reports WHERE order_id = $1', [id]);
    const hasReport = reportResult.rows.length > 0;

    const orderPackage = (order.package || 'professional') as ScanPackage;

    // Read tool output summary from Redis (fast, non-blocking)
    const redisProgress = await getProgressFromRedis(id);
    const toolOutput = redisProgress?.toolOutput as string | undefined;
    const lastCompletedTool = redisProgress?.lastCompletedTool as string | undefined;

    return {
      success: true,
      data: {
        id: order.id,
        domain: order.target_url,
        status: order.status,
        package: orderPackage,
        customerId: order.customer_id,
        estimatedDuration: ESTIMATED_DURATIONS[orderPackage],
        progress: {
          phase: order.current_phase || null,
          currentTool: order.current_tool || null,
          currentHost: order.current_host || null,
          hostsTotal: order.hosts_total || 0,
          hostsCompleted: order.hosts_completed || 0,
          discoveredHosts: order.discovered_hosts || [],
          toolOutput: toolOutput || null,
          lastCompletedTool: lastCompletedTool || null,
        },
        startedAt: order.scan_started_at ? (order.scan_started_at as Date).toISOString() : null,
        finishedAt: order.scan_finished_at ? (order.scan_finished_at as Date).toISOString() : null,
        error: order.error_message || null,
        hasReport,
      },
    };
  });

  // GET /api/orders/:id/report
  server.get<{ Params: OrderParams }>('/api/orders/:id/report', async (request, reply) => {
    const { id } = request.params;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    const result = await query(
      `SELECT r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, o.target_url
       FROM reports r JOIN orders o ON r.order_id = o.id
       WHERE r.order_id = $1`,
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Report not yet available' });
    }

    const report = result.rows[0] as Record<string, unknown>;
    const bucket = report.minio_bucket as string;
    const objectPath = report.minio_path as string;
    const domain = report.target_url as string;
    const fileSize = report.file_size_bytes as number;
    const createdAt = report.created_at as Date;

    const dateStr = createdAt.toISOString().split('T')[0];
    const fileName = `vectiscan-${domain}-${dateStr}.pdf`;

    const stream = await minioClient.getObject(bucket, objectPath);

    return reply
      .header('Content-Type', 'application/pdf')
      .header('Content-Disposition', `attachment; filename="${fileName}"`)
      .header('Content-Length', fileSize)
      .send(stream);
  });

  // GET /api/orders/:id/results — Raw scan results per tool
  server.get<{ Params: OrderParams }>('/api/orders/:id/results', async (request, reply) => {
    const { id } = request.params;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Verify order exists
    const orderResult = await query('SELECT id, status FROM orders WHERE id = $1', [id]);
    if (orderResult.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }

    // Fetch all scan_results for this order
    const resultsQuery = await query(
      `SELECT id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms, created_at
       FROM scan_results
       WHERE order_id = $1
       ORDER BY phase ASC, created_at ASC`,
      [id],
    );

    const results = resultsQuery.rows.map((row: Record<string, unknown>) => ({
      id: row.id,
      hostIp: row.host_ip || null,
      phase: row.phase,
      toolName: row.tool_name,
      rawOutput: row.raw_output || null,
      exitCode: row.exit_code,
      durationMs: row.duration_ms,
      createdAt: (row.created_at as Date).toISOString(),
    }));

    return {
      success: true,
      data: { results },
    };
  });

  // DELETE /api/orders/:id — Cancel a running order
  server.delete<{ Params: OrderParams }>('/api/orders/:id', async (request, reply) => {
    const { id } = request.params;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    const result = await query(
      'SELECT id, status FROM orders WHERE id = $1',
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }

    const order = result.rows[0] as Record<string, unknown>;
    const status = order.status as string;

    // Only cancel orders that are still running
    const cancellableStatuses = ['verification_pending', 'verified', 'created', 'scanning', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_complete', 'report_generating'];
    if (!cancellableStatuses.includes(status)) {
      return reply.status(409).send({
        success: false,
        error: `Order cannot be cancelled in status: ${status}`,
      });
    }

    await query(
      "UPDATE orders SET status = 'cancelled', error_message = 'Vom Benutzer abgebrochen', scan_finished_at = NOW(), updated_at = NOW() WHERE id = $1",
      [id],
    );

    // Notify via Redis Pub/Sub so WebSocket clients get the update
    await publishEvent(id, {
      type: 'status',
      orderId: id,
      status: 'cancelled',
      error: 'Vom Benutzer abgebrochen',
    });

    return { success: true, data: null };
  });

  // Backwards-compat redirects for old scan endpoints
  server.get<{ Params: OrderParams }>('/api/scans/:id', async (request, reply) => {
    return reply.redirect(`/api/orders/${request.params.id}`, 301);
  });

  server.get<{ Params: OrderParams }>('/api/scans/:id/report', async (request, reply) => {
    return reply.redirect(`/api/orders/${request.params.id}/report`, 301);
  });

  server.delete<{ Params: OrderParams }>('/api/scans/:id', async (request, reply) => {
    return reply.redirect(`/api/orders/${request.params.id}`, 307);
  });
}
