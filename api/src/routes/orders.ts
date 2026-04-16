import { FastifyInstance, FastifyReply } from 'fastify';
import { query } from '../lib/db.js';
import { scanQueue, reportQueue, publishEvent, getProgressFromRedis } from '../lib/queue.js';
import { minioClient } from '../lib/minio.js';
import { isValidDomain, isValidTarget } from '../lib/validate.js';
import { generateToken } from '../services/VerificationService.js';
import { verifyJwt } from '../lib/auth.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { audit } from '../lib/audit.js';

async function streamReport(reply: FastifyReply, report: Record<string, unknown>) {
  const bucket = report.minio_bucket as string;
  const objectPath = report.minio_path as string;
  const domain = report.target_url as string;
  const fileSize = report.file_size_bytes as number;
  const createdAt = report.created_at as Date;
  const pkg = (report.package as string) || 'perimeter';
  const version = (report.version as number) || 1;

  const dateStr = createdAt.toISOString().slice(0, 10);
  const timeStr = createdAt.toISOString().slice(11, 16).replace(':', '');
  const fileName = `vectiscan-${domain}-${pkg}-${dateStr}-${timeStr}-v${version}.pdf`;

  const stream = await minioClient.getObject(bucket, objectPath);

  return reply
    .header('Content-Type', 'application/pdf')
    .header('Content-Disposition', `attachment; filename="${fileName}"`)
    .header('Content-Length', fileSize)
    .send(stream);
}

const VALID_PACKAGES = ['webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance', 'tlscompliance'] as const;
type ScanPackage = typeof VALID_PACKAGES[number];

const ESTIMATED_DURATIONS: Record<ScanPackage, string> = {
  webcheck: '~15–20 Minuten',
  perimeter: '~60–90 Minuten',
  compliance: '~65–95 Minuten',
  supplychain: '~65–95 Minuten',
  insurance: '~65–95 Minuten',
  tlscompliance: '~5–10 Minuten',
};

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface CreateOrderBody {
  domain: string;
  package?: string;
}

interface OrderParams {
  id: string;
}

interface FindingParams {
  id: string;
  findingId: string;
}

interface ExcludeBody {
  reason?: string;
}

export async function orderRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/orders — requireAuth, customer_id from JWT
  server.post<{ Body: CreateOrderBody }>('/api/orders', { preHandler: [requireAuth] }, async (request, reply) => {
    const user = request.user!;
    const { domain: rawDomain, package: rawPkg } = request.body || {} as CreateOrderBody;
    const pkg = (rawPkg || 'perimeter') as string;

    const domain = isValidTarget(rawDomain);
    if (!domain) {
      return reply.status(400).send({
        success: false,
        error: 'Invalid domain. Provide a valid FQDN, IPv4, CIDR (/24), or subnet mask (255.255.255.0).',
      });
    }

    if (!VALID_PACKAGES.includes(pkg as ScanPackage)) {
      return reply.status(400).send({
        success: false,
        error: 'Invalid package. Must be webcheck, perimeter, compliance, supplychain, insurance, or tlscompliance.',
      });
    }

    // Resolve customer_id: admins without customer_id get one created
    let customerId = user.customerId;
    if (!customerId) {
      const customerResult = await query<{ id: string }>(
        'INSERT INTO customers (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id',
        [user.email],
      );
      customerId = customerResult.rows[0].id;
    }

    // Check if this customer already has a valid domain verification
    const existingVerification = await query<{ id: string; verification_method: string; expires_at: Date }>(
      `SELECT id, verification_method, expires_at FROM verified_domains
       WHERE customer_id = $1 AND domain = $2 AND expires_at > NOW()`,
      [customerId, domain],
    );
    const alreadyVerified = existingVerification.rows.length > 0;

    // Insert order — skip verification if domain already verified for this customer
    const initialStatus = alreadyVerified ? 'queued' : 'verification_pending';
    const verificationToken = alreadyVerified ? '' : generateToken();
    const result = await query<{ id: string; target_url: string; status: string; package: string; verification_token: string; created_at: Date }>(
      `INSERT INTO orders (customer_id, target_url, package, verification_token, status${alreadyVerified ? ', verified_at, verification_method' : ''})
       VALUES ($1, $2, $3, $4, $5${alreadyVerified ? ', NOW(), $6' : ''})
       RETURNING id, target_url, status, package, verification_token, created_at`,
      alreadyVerified
        ? [customerId, domain, pkg, verificationToken, initialStatus, existingVerification.rows[0].verification_method]
        : [customerId, domain, pkg, verificationToken, initialStatus],
    );

    const order = result.rows[0];

    audit({ orderId: order.id, action: 'order.created', details: { domain, package: pkg, reusedVerification: alreadyVerified }, ip: request.ip });

    // If domain already verified for this customer → start scan immediately
    if (alreadyVerified) {
      await scanQueue.add('scan', {
        orderId: order.id,
        targetDomain: domain,
        package: pkg,
      });

      return reply.status(201).send({
        success: true,
        data: {
          id: order.id,
          domain: order.target_url,
          status: 'queued',
          package: order.package,
          alreadyVerified: true,
        },
      });
    }

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

  // GET /api/orders — requireAuth, admin sees all, customer sees own
  server.get('/api/orders', { preHandler: [requireAuth] }, async (request) => {
    const user = request.user!;

    let sql: string;
    let params: unknown[];

    const baseSelect = `SELECT o.id, o.target_url, o.package, o.status, o.error_message,
                    o.scan_started_at, o.scan_finished_at, o.created_at,
                    o.hosts_total, o.hosts_completed, o.current_tool, o.current_host,
                    c.email,
                    EXISTS(SELECT 1 FROM reports r2 WHERE r2.order_id = o.id) AS has_report,
                    r.findings_data->>'overall_risk' AS overall_risk,
                    r.findings_data->'severity_counts' AS severity_counts
             FROM orders o
             JOIN customers c ON o.customer_id = c.id
             LEFT JOIN reports r ON r.order_id = o.id`;

    if (user.role === 'admin') {
      sql = `${baseSelect} ORDER BY o.created_at DESC`;
      params = [];
    } else {
      sql = `${baseSelect} WHERE o.customer_id = $1 AND o.status IN ('report_complete', 'delivered', 'report_generating') ORDER BY o.created_at DESC`;
      params = [user.customerId];
    }

    const result = await query(sql, params);

    const orders = result.rows.map((row: Record<string, unknown>) => ({
      id: row.id,
      domain: row.target_url,
      email: row.email,
      package: row.package,
      status: row.status,
      hasReport: row.has_report === true || row.has_report === 't',
      error: row.error_message || null,
      hostsTotal: (row.hosts_total as number) || 0,
      hostsCompleted: (row.hosts_completed as number) || 0,
      currentTool: (row.current_tool as string) || null,
      currentHost: (row.current_host as string) || null,
      startedAt: row.scan_started_at ? (row.scan_started_at as Date).toISOString() : null,
      finishedAt: row.scan_finished_at ? (row.scan_finished_at as Date).toISOString() : null,
      createdAt: (row.created_at as Date).toISOString(),
      overallRisk: (row.overall_risk as string) || null,
      severityCounts: row.severity_counts || null,
      businessImpactScore: row.business_impact_score != null ? Number(row.business_impact_score) : null,
    }));

    return { success: true, data: { orders } };
  });

  // POST /api/scans — backwards compat redirect
  server.post('/api/scans', async (_request, reply) => {
    return reply.redirect('/api/orders', 307);
  });

  // GET /api/orders/:id — requireAuth, ownership check
  server.get<{ Params: OrderParams }>('/api/orders/:id', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

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

    // Ownership check: customer can only see own orders
    if (user.role !== 'admin' && order.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Visibility check: customers cannot access internal-status orders
    const customerVisibleStatuses = ['report_complete', 'delivered', 'report_generating'];
    if (user.role !== 'admin' && !customerVisibleStatuses.includes(order.status as string)) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Check if report exists
    const reportResult = await query('SELECT id FROM reports WHERE order_id = $1', [id]);
    const hasReport = reportResult.rows.length > 0;

    const orderPackage = (order.package || 'perimeter') as ScanPackage;

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
        passiveIntelSummary: order.passive_intel_summary || null,
        correlationData: order.correlation_data || null,
        businessImpactScore: order.business_impact_score != null ? Number(order.business_impact_score) : null,
      },
    };
  });

  // GET /api/orders/:id/report — auth via JWT or download_token
  server.get<{ Params: OrderParams }>('/api/orders/:id/report', async (request, reply) => {
    const { id } = request.params;
    const queryParams = request.query as Record<string, string>;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Auth strategy 1: download_token from email link (no login needed)
    const downloadToken = queryParams.download_token;
    if (downloadToken) {
      const tokenCheck = await query(
        `SELECT r.id, r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, r.expires_at, r.version, o.target_url, o.package
         FROM reports r JOIN orders o ON r.order_id = o.id
         WHERE r.order_id = $1 AND r.download_token = $2
         LIMIT 1`,
        [id, downloadToken],
      );

      if (tokenCheck.rows.length === 0) {
        return reply.status(403).send({ success: false, error: 'Invalid download token' });
      }

      const report = tokenCheck.rows[0] as Record<string, unknown>;
      const expiresAt = report.expires_at as Date | null;
      if (expiresAt && new Date() > expiresAt) {
        return reply.status(410).send({ success: false, error: 'Download link expired' });
      }

      // Increment download count
      await query('UPDATE reports SET download_count = download_count + 1 WHERE id = $1', [report.id]);

      audit({ orderId: id, action: 'report.downloaded', details: { via: 'download_token' }, ip: request.ip });

      return streamReport(reply, report);
    }

    // Auth strategy 2: JWT (Bearer token or ?token= query param)
    const header = request.headers.authorization;
    const jwtToken = header?.startsWith('Bearer ') ? header.slice(7) : queryParams.token;

    if (!jwtToken) {
      return reply.status(401).send({ success: false, error: 'Authentication required' });
    }

    let user;
    try {
      user = verifyJwt(jwtToken);
    } catch {
      return reply.status(401).send({ success: false, error: 'Invalid or expired token' });
    }

    // Ownership check
    const ownerCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
    if (ownerCheck.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    if (user.role !== 'admin' && (ownerCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    let result;
    const requestedVersion = (request.query as Record<string, string>).version
      ? parseInt((request.query as Record<string, string>).version, 10)
      : null;

    if (requestedVersion) {
      try {
        result = await query(
          `SELECT r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, r.version, o.target_url, o.package
           FROM reports r JOIN orders o ON r.order_id = o.id
           WHERE r.order_id = $1 AND r.version = $2`,
          [id, requestedVersion],
        );
      } catch {
        // version column doesn't exist yet — fallback
        result = await query(
          `SELECT r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, o.target_url, o.package
           FROM reports r JOIN orders o ON r.order_id = o.id
           WHERE r.order_id = $1 LIMIT 1`,
          [id],
        );
      }
    } else {
      result = await query(
        `SELECT r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, r.version, o.target_url, o.package
         FROM reports r JOIN orders o ON r.order_id = o.id
         WHERE r.order_id = $1 ORDER BY r.created_at DESC LIMIT 1`,
        [id],
      );
    }

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Report not yet available' });
    }

    const reportVersion = (result.rows[0] as Record<string, unknown>).version;
    audit({ orderId: id, action: 'report.downloaded', details: { via: 'jwt', userId: user.sub, version: reportVersion }, ip: request.ip });

    return streamReport(reply, result.rows[0] as Record<string, unknown>);
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

  // GET /api/orders/:id/events — LiveView event replay (AI strategy, configs, tool outputs)
  server.get<{ Params: OrderParams }>('/api/orders/:id/events', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Ownership check
    const orderCheck = await query(
      'SELECT customer_id, discovered_hosts, status, error_message FROM orders WHERE id = $1',
      [id],
    );
    if (orderCheck.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    const order = orderCheck.rows[0] as Record<string, unknown>;
    if (user.role !== 'admin' && order.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Fetch AI strategy and configs from scan_results
    const aiResults = await query(
      `SELECT tool_name, host_ip, raw_output, created_at
       FROM scan_results
       WHERE order_id = $1 AND tool_name IN ('ai_host_strategy', 'ai_phase2_config')
       ORDER BY created_at ASC`,
      [id],
    );

    let aiStrategy = null;
    const aiConfigs: Record<string, unknown> = {};

    for (const row of aiResults.rows as Array<Record<string, unknown>>) {
      try {
        const parsed = JSON.parse(row.raw_output as string);
        if (row.tool_name === 'ai_host_strategy') {
          aiStrategy = parsed;
        } else if (row.tool_name === 'ai_phase2_config' && row.host_ip) {
          aiConfigs[row.host_ip as string] = parsed;
        }
      } catch { /* skip unparseable */ }
    }

    // Fetch tool output summaries (non-AI tools, first 150 chars of raw_output)
    const toolResults = await query(
      `SELECT tool_name, host_ip, LEFT(raw_output, 150) as summary, created_at
       FROM scan_results
       WHERE order_id = $1
         AND tool_name NOT IN ('ai_host_strategy', 'ai_phase2_config', 'ai_host_skip')
         AND exit_code >= 0
       ORDER BY created_at ASC`,
      [id],
    );

    const toolOutputs = (toolResults.rows as Array<Record<string, unknown>>).map(row => ({
      tool: row.tool_name,
      host: row.host_ip || '',
      summary: ((row.summary as string) || '').split('\n')[0].slice(0, 100),
      ts: new Date(row.created_at as string).toISOString(),
    }));

    // Load AI debug prompts/responses
    const aiDebugRows = await query(
      `SELECT tool_name, host_ip, raw_output FROM scan_results
       WHERE order_id = $1 AND tool_name LIKE '%_debug' ORDER BY created_at`,
      [id],
    );

    const aiDebug: Record<string, unknown> = {};
    for (const row of aiDebugRows.rows as Array<Record<string, unknown>>) {
      try {
        const data = JSON.parse(row.raw_output as string);
        const key = (row.tool_name as string).replace('_debug', '');
        if (row.host_ip) {
          // Per-host debug (phase2_config)
          if (!aiDebug[key]) aiDebug[key] = {};
          (aiDebug[key] as Record<string, unknown>)[row.host_ip as string] = data;
        } else {
          aiDebug[key] = data;
        }
      } catch { /* skip unparseable */ }
    }

    // Aggregate AI costs for this scan
    let totalCostUsd = 0;
    const costBreakdown: Array<{step: string; model: string; tokens: number; cost_usd: number}> = [];

    // Cost data is in _debug entries and report_cost
    const costRows = await query(
      `SELECT tool_name, raw_output FROM scan_results
       WHERE order_id = $1 AND (tool_name LIKE '%_debug' OR tool_name = 'report_cost')
       ORDER BY created_at`,
      [id],
    );

    for (const row of costRows.rows as Array<Record<string, unknown>>) {
      try {
        const data = JSON.parse(row.raw_output as string);
        // _debug entries have cost nested: {cost: {...}}
        // report_cost entries ARE the cost object directly: {model: ..., total_cost_usd: ...}
        const cost = data.cost || (data.total_cost_usd ? data : null);
        if (cost && typeof cost === 'object' && cost.total_cost_usd) {
          totalCostUsd += cost.total_cost_usd;
          const toolName = row.tool_name as string;
          costBreakdown.push({
            step: toolName === 'report_cost' ? 'report_generation' : toolName.replace('_debug', ''),
            model: cost.model || 'unknown',
            tokens: (cost.input_tokens || 0) + (cost.output_tokens || 0),
            cost_usd: cost.total_cost_usd,
          });
        }
      } catch { /* skip unparseable */ }
    }

    // Load false positive details from phase3 correlation
    const fpRow = await query(
      `SELECT raw_output FROM scan_results
       WHERE order_id = $1 AND tool_name = 'phase3_correlation' LIMIT 1`,
      [id],
    );

    let falsePositives = null;
    if (fpRow.rows.length > 0) {
      try {
        const phase3Data = JSON.parse((fpRow.rows[0] as Record<string, unknown>).raw_output as string);
        falsePositives = {
          count: phase3Data.false_positives_count || 0,
          by_reason: phase3Data.fp_by_reason || {},
          details: phase3Data.fp_details || [],
        };
      } catch { /* skip unparseable */ }
    }

    // Fetch Claude report debug data from MinIO (best-effort, admin only)
    let claudeDebug = null;
    if (user.role === 'admin') {
      try {
        const stream = await minioClient.getObject('scan-debug', `${id}-claude.json`);
        const chunks: Buffer[] = [];
        for await (const chunk of stream) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        claudeDebug = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
      } catch {
        // File doesn't exist or MinIO unavailable — not critical
      }
    }

    return {
      success: true,
      data: {
        aiStrategy,
        aiConfigs,
        aiDebug,
        toolOutputs,
        discoveredHosts: order.discovered_hosts || [],
        error: order.error_message || null,
        falsePositives,
        claudeDebug,
        costs: totalCostUsd > 0 ? { total_usd: Math.round(totalCostUsd * 10000) / 10000, breakdown: costBreakdown } : null,
      },
    };
  });

  // GET /api/orders/:id/findings — structured findings from report
  server.get<{ Params: OrderParams }>('/api/orders/:id/findings', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Ownership check
    const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
    if (orderCheck.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    if (user.role !== 'admin' && (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    const result = await query(
      'SELECT findings_data FROM reports WHERE order_id = $1 LIMIT 1',
      [id],
    );
    if (result.rows.length === 0 || !(result.rows[0] as Record<string, unknown>).findings_data) {
      return reply.status(404).send({ success: false, error: 'Keine Befunddaten verfügbar' });
    }

    // Load excluded findings (table may not exist yet — graceful fallback)
    let excludedIds: string[] = [];
    let exclusionRows: Array<Record<string, unknown>> = [];
    try {
      const exclusions = await query(
        'SELECT finding_id, reason, created_at FROM finding_exclusions WHERE order_id = $1',
        [id],
      );
      excludedIds = exclusions.rows.map((r: Record<string, unknown>) => r.finding_id as string);
      exclusionRows = exclusions.rows as Array<Record<string, unknown>>;
    } catch {
      // finding_exclusions table doesn't exist yet — skip
    }

    const findingsData = (result.rows[0] as Record<string, unknown>).findings_data as Record<string, unknown>;
    return {
      success: true,
      data: {
        ...findingsData,
        excluded_finding_ids: excludedIds,
        exclusions: exclusionRows.map((r) => ({
          finding_id: r.finding_id,
          reason: r.reason,
          created_at: r.created_at ? (r.created_at as Date).toISOString() : null,
        })),
      },
    };
  });

  // GET /api/orders/:id/report-versions — list all report versions
  server.get<{ Params: OrderParams }>('/api/orders/:id/report-versions', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Ownership check
    const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
    if (orderCheck.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    if (user.role !== 'admin' && (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Try query with version column first; fallback if migration 011 hasn't run
    let versions: Array<Record<string, unknown>>;
    try {
      const result = await query(
        `SELECT version, created_at, file_size_bytes, excluded_findings, findings_data->'severity_counts' AS severity_counts
         FROM reports WHERE order_id = $1
         ORDER BY version DESC`,
        [id],
      );
      versions = result.rows as Array<Record<string, unknown>>;
    } catch {
      // version column doesn't exist yet — fallback
      const result = await query(
        `SELECT created_at, file_size_bytes, findings_data->'severity_counts' AS severity_counts
         FROM reports WHERE order_id = $1`,
        [id],
      );
      versions = result.rows as Array<Record<string, unknown>>;
    }

    const sumSeverityCounts = (counts: unknown): number => {
      if (!counts || typeof counts !== 'object') return 0;
      return Object.values(counts as Record<string, number>).reduce((sum, v) => sum + (typeof v === 'number' ? v : 0), 0);
    };

    return {
      success: true,
      data: {
        versions: versions.map((row, idx) => ({
          version: row.version ?? 1,
          createdAt: row.created_at ? (row.created_at as Date).toISOString() : null,
          findingsCount: sumSeverityCounts(row.severity_counts),
          excludedCount: (row.excluded_findings as string[] || []).length,
          excludedFindings: row.excluded_findings || [],
          fileSizeBytes: row.file_size_bytes || 0,
          isCurrent: idx === 0,
        })),
      },
    };
  });

  // POST /api/orders/:id/findings/:findingId/exclude — exclude a finding
  server.post<{ Params: FindingParams; Body: ExcludeBody }>(
    '/api/orders/:id/findings/:findingId/exclude',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, findingId } = request.params;
      const user = request.user!;
      const { reason } = request.body || {};

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      // Ownership check
      const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      if (user.role !== 'admin' && (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
        return reply.status(403).send({ success: false, error: 'Access denied' });
      }

      await query(
        `INSERT INTO finding_exclusions (order_id, finding_id, excluded_by, reason)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (order_id, finding_id) DO UPDATE SET reason = EXCLUDED.reason`,
        [id, findingId, user.sub, reason || null],
      );

      audit({ orderId: id, action: 'finding.excluded', details: { findingId, reason, userId: user.sub }, ip: request.ip });

      return { success: true, data: null };
    },
  );

  // DELETE /api/orders/:id/findings/:findingId/exclude — unexclude a finding
  server.delete<{ Params: FindingParams }>(
    '/api/orders/:id/findings/:findingId/exclude',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, findingId } = request.params;
      const user = request.user!;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      // Ownership check
      const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      if (user.role !== 'admin' && (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
        return reply.status(403).send({ success: false, error: 'Access denied' });
      }

      await query(
        'DELETE FROM finding_exclusions WHERE order_id = $1 AND finding_id = $2',
        [id, findingId],
      );

      audit({ orderId: id, action: 'finding.unexcluded', details: { findingId, userId: user.sub }, ip: request.ip });

      return { success: true, data: null };
    },
  );

  // POST /api/orders/:id/regenerate-report — regenerate report with excluded findings
  server.post<{ Params: OrderParams }>(
    '/api/orders/:id/regenerate-report',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      // Ownership check + get order details
      const orderCheck = await query(
        'SELECT customer_id, target_url, package, status FROM orders WHERE id = $1',
        [id],
      );
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      const order = orderCheck.rows[0] as Record<string, unknown>;
      if (user.role !== 'admin' && order.customer_id !== user.customerId) {
        return reply.status(403).send({ success: false, error: 'Access denied' });
      }

      // Allow regeneration for completed orders and failed reports (scan data still exists)
      const status = order.status as string;
      const allowedStatuses = ['report_complete', 'completed', 'failed', 'report_generating', 'cancelled'];
      if (!allowedStatuses.includes(status)) {
        return reply.status(409).send({
          success: false,
          error: `Report kann nur bei abgeschlossenen oder fehlgeschlagenen Orders neu generiert werden (aktuell: ${status})`,
        });
      }

      // Load excluded findings
      const exclusions = await query(
        'SELECT finding_id, reason FROM finding_exclusions WHERE order_id = $1',
        [id],
      );
      const excludedFindings = exclusions.rows.map((r: Record<string, unknown>) => ({
        finding_id: r.finding_id,
        reason: r.reason,
      }));

      // Update order status
      await query(
        "UPDATE orders SET status = 'report_generating', updated_at = NOW() WHERE id = $1",
        [id],
      );

      // Enqueue report job with excluded findings
      await reportQueue.add('report', {
        orderId: id,
        rawDataPath: `${id}.tar.gz`,
        package: order.package as string,
        excludedFindings,
        regenerate: true,
      });

      audit({
        orderId: id,
        action: 'report.regenerate',
        details: { userId: user.sub, excludedCount: excludedFindings.length },
        ip: request.ip,
      });

      // Notify WebSocket clients
      await publishEvent(id, {
        type: 'status',
        orderId: id,
        status: 'report_generating',
      });

      return {
        success: true,
        data: { message: 'Report wird neu generiert' },
      };
    },
  );

  // ── Admin Review Workflow ──────────────────────────────────

  // GET /api/admin/pending-reviews — list all orders pending admin review
  server.get('/api/admin/pending-reviews', { preHandler: [requireAuth, requireAdmin] }, async () => {
    const result = await query(
      `SELECT o.id, o.target_url AS domain, o.package, o.status, o.created_at, o.scan_finished_at,
              o.correlation_data, o.business_impact_score,
              c.email AS customer_email,
              r.findings_data
       FROM orders o
       LEFT JOIN customers c ON c.id = o.customer_id
       LEFT JOIN reports r ON r.order_id = o.id AND r.superseded_by IS NULL
       WHERE o.status = 'pending_review'
       ORDER BY o.scan_finished_at ASC`,
    );

    const reviews = result.rows.map((row: Record<string, unknown>) => {
      const findingsData = row.findings_data as Record<string, unknown> | null;
      return {
        id: row.id,
        domain: row.domain,
        package: row.package,
        status: row.status,
        customerEmail: row.customer_email,
        createdAt: row.created_at,
        scanFinishedAt: row.scan_finished_at,
        businessImpactScore: row.business_impact_score,
        severityCounts: findingsData?.severity_counts || null,
      };
    });

    return { success: true, data: { reviews } };
  });

  // POST /api/admin/orders/:id/approve — approve a pending review, trigger report generation
  server.post<{ Params: OrderParams }>(
    '/api/admin/orders/:id/approve',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      const orderCheck = await query(
        'SELECT status, target_url, package, customer_id FROM orders WHERE id = $1',
        [id],
      );
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }

      const order = orderCheck.rows[0] as Record<string, unknown>;
      if (order.status !== 'pending_review') {
        return reply.status(409).send({
          success: false,
          error: `Order ist nicht im Review-Status (aktuell: ${order.status})`,
        });
      }

      // Load excluded findings (admin may have marked FPs before approving)
      const exclusions = await query(
        'SELECT finding_id, reason FROM finding_exclusions WHERE order_id = $1',
        [id],
      );
      const excludedFindings = exclusions.rows.map((r: Record<string, unknown>) => ({
        finding_id: r.finding_id,
        reason: r.reason,
      }));

      // Mark as approved
      await query(
        `UPDATE orders SET status = 'approved', reviewed_by = $1, reviewed_at = NOW(),
         updated_at = NOW() WHERE id = $2`,
        [user.sub, id],
      );

      // Enqueue report generation
      await reportQueue.add('report', {
        orderId: id,
        rawDataPath: `${id}.tar.gz`,
        package: order.package as string,
        excludedFindings,
      });

      // Update status to report_generating
      await query(
        "UPDATE orders SET status = 'report_generating', updated_at = NOW() WHERE id = $1",
        [id],
      );

      await publishEvent(id, { type: 'status', orderId: id, status: 'report_generating' });

      audit({
        orderId: id,
        action: 'order.approved',
        details: { userId: user.sub, excludedCount: excludedFindings.length },
        ip: request.ip,
      });

      return { success: true, data: { message: 'Review genehmigt, Report wird generiert.' } };
    },
  );

  // POST /api/admin/orders/:id/reject — reject a pending review
  server.post<{ Params: OrderParams }>(
    '/api/admin/orders/:id/reject',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;
      const body = request.body as Record<string, unknown> | null;
      const reason = (body?.reason as string) || '';

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      const orderCheck = await query('SELECT status FROM orders WHERE id = $1', [id]);
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }

      const order = orderCheck.rows[0] as Record<string, unknown>;
      if (order.status !== 'pending_review') {
        return reply.status(409).send({
          success: false,
          error: `Order ist nicht im Review-Status (aktuell: ${order.status})`,
        });
      }

      await query(
        `UPDATE orders SET status = 'rejected', reviewed_by = $1, reviewed_at = NOW(),
         review_notes = $2, updated_at = NOW() WHERE id = $3`,
        [user.sub, reason, id],
      );

      await publishEvent(id, { type: 'status', orderId: id, status: 'rejected' });

      audit({
        orderId: id,
        action: 'order.rejected',
        details: { userId: user.sub, reason },
        ip: request.ip,
      });

      return { success: true, data: { message: 'Review abgelehnt.' } };
    },
  );

  // DELETE /api/orders/:id — soft cancel or admin hard delete
  server.delete<{ Params: OrderParams }>('/api/orders/:id', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;
    const queryParams = request.query as Record<string, string>;
    const permanent = queryParams.permanent === 'true';

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    const result = await query(
      'SELECT id, status, customer_id FROM orders WHERE id = $1',
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }

    const order = result.rows[0] as Record<string, unknown>;

    // Ownership check
    if (user.role !== 'admin' && order.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Admin hard delete: ?permanent=true
    if (permanent) {
      if (user.role !== 'admin') {
        return reply.status(403).send({ success: false, error: 'Only admins can permanently delete orders' });
      }

      // Clean up MinIO objects (best-effort, don't block on errors)
      try {
        await minioClient.removeObject('scan-rawdata', `${id}.tar.gz`);
      } catch { /* ignore — file may not exist */ }
      try {
        await minioClient.removeObject('scan-reports', `${id}.pdf`);
      } catch { /* ignore — file may not exist */ }

      // Delete audit_log entries (no CASCADE on this FK)
      await query('DELETE FROM audit_log WHERE order_id = $1', [id]);

      // Delete order (CASCADE removes scan_results + reports)
      await query('DELETE FROM orders WHERE id = $1', [id]);

      // orderId: null because the order + its audit_log entries were just deleted (FK constraint)
      audit({ orderId: null, action: 'order.deleted', details: { deletedOrderId: id, admin: user.email, domain: order.target_url }, ip: request.ip });

      return { success: true, data: null };
    }

    // Soft cancel: only for running orders
    const status = order.status as string;
    const cancellableStatuses = ['verification_pending', 'verified', 'created', 'queued', 'scanning', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_complete', 'report_generating'];
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

    audit({ orderId: id, action: 'order.cancelled', details: { userId: user.sub, previousStatus: status }, ip: request.ip });

    // Notify via Redis Pub/Sub so WebSocket clients get the update
    await publishEvent(id, {
      type: 'status',
      orderId: id,
      status: 'cancelled',
      error: 'Vom Benutzer abgebrochen',
    });

    return { success: true, data: null };
  });

  // --- Admin: Re-queue report generation ---
  server.post<{ Params: OrderParams }>(
    '/api/orders/:id/requeue-report',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID' });
      }

      // Fetch order
      const orderResult = await query(
        'SELECT id, target_url, package, status FROM orders WHERE id = $1',
        [id],
      );
      if (orderResult.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      const order = orderResult.rows[0] as Record<string, unknown>;
      const domain = order.target_url as string;

      // Fetch host inventory from scan_results (ai_host_strategy stores it)
      const invResult = await query(
        `SELECT raw_output FROM scan_results
         WHERE order_id = $1 AND tool_name = 'ai_host_strategy' LIMIT 1`,
        [id],
      );
      let hostInventory: Record<string, unknown> = { hosts: [], domain };
      if (invResult.rows.length > 0) {
        try {
          const parsed = JSON.parse((invResult.rows[0] as Record<string, unknown>).raw_output as string);
          if (parsed.hosts) hostInventory = parsed;
        } catch { /* use default */ }
      }

      // Fetch tech profiles from scan_results
      const techResult = await query(
        `SELECT raw_output FROM scan_results
         WHERE order_id = $1 AND tool_name = 'ai_tech_analysis_debug' LIMIT 1`,
        [id],
      );
      let techProfiles: unknown[] = [];
      if (techResult.rows.length > 0) {
        try {
          techProfiles = JSON.parse((techResult.rows[0] as Record<string, unknown>).raw_output as string);
        } catch { /* use default */ }
      }

      // Fetch phase3 correlation data
      const p3Result = await query(
        `SELECT raw_output FROM scan_results
         WHERE order_id = $1 AND tool_name = 'phase3_correlation' LIMIT 1`,
        [id],
      );
      let phase3Data: Record<string, unknown> | null = null;
      if (p3Result.rows.length > 0) {
        try {
          phase3Data = JSON.parse((p3Result.rows[0] as Record<string, unknown>).raw_output as string);
        } catch { /* skip */ }
      }

      // Reset status to scan_complete so the report worker picks it up
      await query(
        `UPDATE orders SET status = 'scan_complete', error_message = NULL WHERE id = $1`,
        [id],
      );

      // Build and enqueue report job
      const jobPayload: Record<string, unknown> = {
        orderId: id,
        rawDataPath: `${id}.tar.gz`,
        hostInventory,
        techProfiles,
        package: order.package || 'perimeter',
      };

      if (phase3Data) {
        jobPayload.enrichment = phase3Data.enrichment || {};
        jobPayload.correlatedFindings = phase3Data.correlated_findings || [];
        jobPayload.businessImpactScore = phase3Data.business_impact_score || 0.0;
        jobPayload.phase3Summary = phase3Data.phase3_summary || {};
      }

      await reportQueue.add('report', jobPayload);

      await audit({ orderId: id, action: 'report.regenerate', ip: request.ip });
      server.log.info({ orderId: id }, 'Report job re-queued by admin');

      return { success: true, data: { message: 'Report job re-queued', orderId: id } };
    },
  );

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
