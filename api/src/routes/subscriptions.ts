/**
 * Subscription management routes (Multi-Target).
 *
 * Customers can create subscriptions mit bis zu max_domains Target-Zeilen.
 * Jedes Target durchlaeuft Pre-Check + Admin-Review, bevor es fuer
 * Abo-Scans freigeschaltet wird.
 */
import { FastifyInstance } from 'fastify';
import { query } from '../lib/db.js';
import { scanQueue, publishEvent, enqueuePrecheck } from '../lib/queue.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { audit } from '../lib/audit.js';
import { validateTarget, validateTargetBatch } from '../lib/validate.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VALID_PACKAGES = ['perimeter', 'insurance', 'compliance', 'supplychain', 'webcheck', 'tlscompliance'];

export async function subscriptionRoutes(server: FastifyInstance): Promise<void> {

  // ── Customer Endpoints ──────────────────────────────────

  // POST /api/subscriptions — create subscription with targets[]
  server.post('/api/subscriptions', { preHandler: [requireAuth] }, async (request, reply) => {
    const user = request.user!;
    const body = request.body as Record<string, unknown> | null;

    const pkg = (body?.package as string || 'perimeter').toLowerCase();
    if (!VALID_PACKAGES.includes(pkg)) {
      return reply.status(400).send({ success: false, error: `Ungültiges Paket: ${pkg}` });
    }

    const scanInterval = (body?.scanInterval as string || 'monthly').toLowerCase();
    if (!['weekly', 'monthly', 'quarterly'].includes(scanInterval)) {
      return reply.status(400).send({ success: false, error: 'Ungültiges Intervall. Erlaubt: weekly, monthly, quarterly' });
    }

    const rawTargets = (body?.targets as Array<{ raw_input?: unknown; exclusions?: unknown }>) || [];
    const batch = validateTargetBatch(rawTargets);
    if (batch.errors.length > 0 || batch.targets.some(t => !t.valid)) {
      return reply.status(400).send({ success: false, error: 'target_validation_failed', data: batch });
    }

    const reportEmails = (body?.reportEmails as string[]) || [user.email];

    // Resolve customer_id
    let customerId = user.customerId;
    if (!customerId) {
      const custResult = await query<{ id: string }>(
        'INSERT INTO customers (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id',
        [user.email],
      );
      customerId = custResult.rows[0].id;
    }

    const now = new Date();
    const expiresAt = new Date(now);
    expiresAt.setFullYear(expiresAt.getFullYear() + 1);

    const subResult = await query<{ id: string }>(
      `INSERT INTO subscriptions (customer_id, package, status, scan_interval, report_emails,
       started_at, expires_at, amount_cents)
       VALUES ($1, $2, 'active', $3, $4, NOW(), $5, 0)
       RETURNING id`,
      [customerId, pkg, scanInterval, reportEmails, expiresAt.toISOString()],
    );
    const subscriptionId = subResult.rows[0].id;

    const targetIds: string[] = [];
    const targetStubs: Array<Record<string, unknown>> = [];
    for (let i = 0; i < batch.targets.length; i++) {
      const t = batch.targets[i];
      const exclusions = Array.isArray(rawTargets[i]?.exclusions)
        ? (rawTargets[i].exclusions as unknown[]).filter(e => typeof e === 'string') as string[]
        : [];
      const ins = await query<{ id: string }>(
        `INSERT INTO scan_targets
           (subscription_id, raw_input, canonical, target_type, discovery_policy, exclusions, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending_precheck')
         RETURNING id`,
        [subscriptionId, t.raw_input, t.canonical, t.target_type, t.policy_default, exclusions],
      );
      targetIds.push(ins.rows[0].id);
      targetStubs.push({
        id: ins.rows[0].id,
        raw_input: t.raw_input,
        canonical: t.canonical,
        target_type: t.target_type,
        discovery_policy: t.policy_default,
        status: 'pending_precheck',
      });
    }

    await enqueuePrecheck({ subscriptionId, targetIds });

    audit({
      action: 'subscription.created',
      details: { subscriptionId, package: pkg, targetCount: batch.targets.length, scanInterval, userId: user.sub },
      ip: request.ip,
    });

    return {
      success: true,
      data: {
        id: subscriptionId,
        package: pkg,
        status: 'active',
        scanInterval,
        targets: targetStubs,
        expiresAt: expiresAt.toISOString(),
        message: 'Abo erstellt. Targets durchlaufen Pre-Check + Admin-Review.',
      },
    };
  });

  // GET /api/subscriptions — list (customer: own, admin: all)
  server.get('/api/subscriptions', { preHandler: [requireAuth] }, async (request) => {
    const user = request.user!;

    let customerId = user.customerId;
    if (!customerId) {
      const custResult = await query<{ id: string }>('SELECT id FROM customers WHERE email = $1', [user.email]);
      if (custResult.rows.length === 0) return { success: true, data: { subscriptions: [] } };
      customerId = custResult.rows[0].id;
    }

    const isAdminUser = user.role === 'admin';
    const subsResult = isAdminUser
      ? await query(
          `SELECT s.*, c.email AS customer_email
           FROM subscriptions s
           LEFT JOIN customers c ON c.id = s.customer_id
           ORDER BY s.created_at DESC`,
        )
      : await query(
          `SELECT s.*, c.email AS customer_email
           FROM subscriptions s
           LEFT JOIN customers c ON c.id = s.customer_id
           WHERE s.customer_id = $1
           ORDER BY s.created_at DESC`,
          [customerId],
        );

    const subscriptions = [];
    for (const sub of subsResult.rows as Array<Record<string, unknown>>) {
      const targetsResult = await query(
        `SELECT id, raw_input, canonical, target_type, discovery_policy, exclusions, status
         FROM scan_targets WHERE subscription_id = $1 ORDER BY created_at`,
        [sub.id],
      );
      subscriptions.push({
        id: sub.id,
        customerEmail: sub.customer_email,
        package: sub.package,
        status: sub.status,
        scanInterval: sub.scan_interval,
        maxDomains: sub.max_domains,
        maxHosts: sub.max_hosts,
        maxCidrPrefix: sub.max_cidr_prefix,
        maxRescans: sub.max_rescans,
        rescansUsed: sub.rescans_used,
        reportEmails: sub.report_emails,
        startedAt: sub.started_at,
        expiresAt: sub.expires_at,
        lastScanAt: sub.last_scan_at,
        createdAt: sub.created_at,
        targets: (targetsResult.rows as Array<Record<string, unknown>>).map(t => ({
          id: t.id,
          raw_input: t.raw_input,
          canonical: t.canonical,
          target_type: t.target_type,
          discovery_policy: t.discovery_policy,
          exclusions: t.exclusions,
          status: t.status,
        })),
      });
    }

    return { success: true, data: { subscriptions } };
  });

  // POST /api/subscriptions/:id/targets — customer adds a single target to existing sub
  server.post<{ Params: { id: string } }>(
    '/api/subscriptions/:id/targets',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;
      const body = request.body as Record<string, unknown> | null;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid subscription ID' });
      }

      const validation = validateTarget(body?.raw_input);
      if (!validation.valid) {
        return reply.status(400).send({ success: false, error: 'target_validation_failed', data: validation });
      }

      const sub = await query(
        'SELECT customer_id, max_domains FROM subscriptions WHERE id = $1',
        [id],
      );
      if (sub.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Abo nicht gefunden.' });
      }
      const subRow = sub.rows[0] as Record<string, unknown>;

      // Ownership
      let customerId = user.customerId;
      if (!customerId) {
        const custResult = await query<{ id: string }>('SELECT id FROM customers WHERE email = $1', [user.email]);
        if (custResult.rows.length > 0) customerId = custResult.rows[0].id;
      }
      if (user.role !== 'admin' && subRow.customer_id !== customerId) {
        return reply.status(403).send({ success: false, error: 'Zugriff verweigert.' });
      }

      // Input-Zeilen-Limit
      const countRes = await query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM scan_targets
         WHERE subscription_id = $1 AND status NOT IN ('rejected', 'removed')`,
        [id],
      );
      if (parseInt(countRes.rows[0].count, 10) >= (subRow.max_domains as number)) {
        return reply.status(409).send({ success: false, error: `Maximale Target-Anzahl (${subRow.max_domains}) erreicht.` });
      }

      const exclusions = Array.isArray(body?.exclusions)
        ? (body!.exclusions as unknown[]).filter(e => typeof e === 'string') as string[]
        : [];

      const ins = await query<{ id: string }>(
        `INSERT INTO scan_targets
           (subscription_id, raw_input, canonical, target_type, discovery_policy, exclusions, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending_precheck')
         RETURNING id`,
        [id, validation.raw_input, validation.canonical, validation.target_type, validation.policy_default, exclusions],
      );
      const targetId = ins.rows[0].id;

      await enqueuePrecheck({ subscriptionId: id, targetIds: [targetId] });

      audit({
        action: 'subscription.target_requested',
        details: { subscriptionId: id, targetId, raw: validation.raw_input, userId: user.sub },
        ip: request.ip,
      });

      return {
        success: true,
        data: {
          id: targetId,
          raw_input: validation.raw_input,
          canonical: validation.canonical,
          target_type: validation.target_type,
          discovery_policy: validation.policy_default,
          status: 'pending_precheck',
        },
      };
    },
  );

  // DELETE /api/subscriptions/:id/targets/:targetId — customer removes a target
  server.delete<{ Params: { id: string; targetId: string } }>(
    '/api/subscriptions/:id/targets/:targetId',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, targetId } = request.params;
      const user = request.user!;
      if (!UUID_REGEX.test(id) || !UUID_REGEX.test(targetId)) {
        return reply.status(400).send({ success: false, error: 'Invalid ID' });
      }

      const sub = await query('SELECT customer_id FROM subscriptions WHERE id = $1', [id]);
      if (sub.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Abo nicht gefunden.' });
      }
      let customerId = user.customerId;
      if (!customerId) {
        const custResult = await query<{ id: string }>('SELECT id FROM customers WHERE email = $1', [user.email]);
        if (custResult.rows.length > 0) customerId = custResult.rows[0].id;
      }
      if (user.role !== 'admin' && (sub.rows[0] as Record<string, unknown>).customer_id !== customerId) {
        return reply.status(403).send({ success: false, error: 'Zugriff verweigert.' });
      }

      const upd = await query(
        `UPDATE scan_targets SET status = 'removed', updated_at = NOW()
         WHERE id = $1 AND subscription_id = $2 RETURNING raw_input`,
        [targetId, id],
      );
      if (upd.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Target nicht gefunden.' });
      }

      audit({
        action: 'subscription.target_removed',
        details: { subscriptionId: id, targetId, userId: user.sub },
        ip: request.ip,
      });
      return { success: true, data: { message: 'Target entfernt.' } };
    },
  );

  // POST /api/subscriptions/:id/rescan — trigger an ad-hoc rescan
  // Body optional: { targetId? } — wenn gesetzt, nur dieses Target; sonst alle approved
  server.post<{ Params: { id: string } }>(
    '/api/subscriptions/:id/rescan',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;
      const body = request.body as Record<string, unknown> | null;
      const filterTargetId = body?.targetId ? String(body.targetId) : null;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid subscription ID' });
      }

      const sub = await query(
        'SELECT customer_id, package, max_rescans, rescans_used, status FROM subscriptions WHERE id = $1',
        [id],
      );
      if (sub.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Abo nicht gefunden.' });
      }
      const subRow = sub.rows[0] as Record<string, unknown>;
      if (subRow.status !== 'active') {
        return reply.status(409).send({ success: false, error: 'Abo ist nicht aktiv.' });
      }

      const isAdminTrigger = user.role === 'admin';
      if (!isAdminTrigger && (subRow.rescans_used as number) >= (subRow.max_rescans as number)) {
        return reply.status(409).send({
          success: false,
          error: `Re-Scan-Kontingent erschöpft (${subRow.rescans_used}/${subRow.max_rescans}).`,
        });
      }

      const approvedTargets = await query(
        `SELECT id, canonical, discovery_policy, exclusions FROM scan_targets
         WHERE subscription_id = $1 AND status = 'approved'
         ${filterTargetId ? 'AND id = $2' : ''}`,
        filterTargetId ? [id, filterTargetId] : [id],
      );
      if (approvedTargets.rows.length === 0) {
        return reply.status(400).send({ success: false, error: 'Keine freigegebenen Targets fuer Re-Scan.' });
      }

      let customerId = user.customerId;
      if (!customerId) {
        const custResult = await query<{ id: string }>('SELECT id FROM customers WHERE email = $1', [user.email]);
        if (custResult.rows.length > 0) customerId = custResult.rows[0].id;
      }

      const displayName = approvedTargets.rows.length === 1
        ? (approvedTargets.rows[0] as Record<string, unknown>).canonical as string
        : `multi-target (${approvedTargets.rows.length})`;

      const orderResult = await query<{ id: string }>(
        `INSERT INTO orders (customer_id, target_url, package, status, subscription_id, is_rescan, target_count, verified_at)
         VALUES ($1, $2, $3, 'queued', $4, true, $5, NOW())
         RETURNING id`,
        [customerId, displayName, subRow.package, id, approvedTargets.rows.length],
      );
      const orderId = orderResult.rows[0].id;

      // Snapshot der approved Targets in scan_run_targets
      for (const row of approvedTargets.rows as Array<Record<string, unknown>>) {
        await query(
          `INSERT INTO scan_run_targets
             (order_id, scan_target_id, in_scope, snapshot_discovery_policy, snapshot_exclusions)
           VALUES ($1, $2, true, $3, $4)`,
          [orderId, row.id, row.discovery_policy, row.exclusions],
        );
      }

      if (!isAdminTrigger) {
        await query(
          'UPDATE subscriptions SET rescans_used = rescans_used + 1, updated_at = NOW() WHERE id = $1',
          [id],
        );
      }

      await scanQueue.add('scan', { orderId, package: subRow.package });
      await publishEvent(orderId, { type: 'status', orderId, status: 'queued' });

      audit({
        action: 'subscription.rescan',
        details: { subscriptionId: id, orderId, targetCount: approvedTargets.rows.length, userId: user.sub, triggeredBy: isAdminTrigger ? 'admin' : 'customer' },
        ip: request.ip,
      });

      return {
        success: true,
        data: {
          orderId,
          targetCount: approvedTargets.rows.length,
          message: isAdminTrigger ? 'Admin-Re-Scan gestartet (Kontingent unverändert).' : 'Re-Scan gestartet.',
        },
      };
    },
  );

  // ── Subscription Posture (PR-Posture, 2026-05-03) ──────────────────────
  // Aggregierte Sicherheits-Posture ueber alle Scans der Subscription.
  // Ersetzt naive Severity-Counts-Summation in grouping.ts.

  async function _checkSubscriptionAccess(
    subId: string,
    user: { customerId: string | null; role: string; sub: string; email: string },
  ): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
    if (!UUID_REGEX.test(subId)) {
      return { ok: false, status: 400, error: 'Invalid subscription ID' };
    }
    const sub = await query<{ customer_id: string }>(
      'SELECT customer_id FROM subscriptions WHERE id = $1',
      [subId],
    );
    if (sub.rows.length === 0) {
      return { ok: false, status: 404, error: 'Abo nicht gefunden.' };
    }
    if (user.role !== 'admin' && user.customerId !== sub.rows[0].customer_id) {
      return { ok: false, status: 403, error: 'Kein Zugriff auf dieses Abo.' };
    }
    return { ok: true };
  }

  // GET /api/subscriptions/:id/posture — aktueller Posture-Status
  server.get<{ Params: { id: string } }>(
    '/api/subscriptions/:id/posture',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const access = await _checkSubscriptionAccess(id, request.user!);
      if (!access.ok) return reply.status(access.status).send({ success: false, error: access.error });

      const res = await query(
        `SELECT subscription_id, last_scan_order_id, last_aggregated_at,
                severity_counts, posture_score, trend_direction, updated_at
           FROM subscription_posture
          WHERE subscription_id = $1`,
        [id],
      );
      if (res.rows.length === 0) {
        // Noch keine Aggregation gelaufen → leere Default-Posture
        return {
          success: true,
          data: {
            subscriptionId: id,
            lastScanOrderId: null,
            lastAggregatedAt: null,
            severityCounts: { open: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, total_open: 0 },
            postureScore: null,
            trendDirection: 'unknown',
            updatedAt: null,
          },
        };
      }
      const r = res.rows[0] as Record<string, unknown>;
      return {
        success: true,
        data: {
          subscriptionId: r.subscription_id,
          lastScanOrderId: r.last_scan_order_id,
          lastAggregatedAt: r.last_aggregated_at,
          severityCounts: r.severity_counts,
          postureScore: r.posture_score != null ? Number(r.posture_score) : null,
          trendDirection: r.trend_direction,
          updatedAt: r.updated_at,
        },
      };
    },
  );

  // GET /api/subscriptions/:id/findings — alle consolidated_findings
  server.get<{ Params: { id: string }; Querystring: { status?: string; severity?: string } }>(
    '/api/subscriptions/:id/findings',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const access = await _checkSubscriptionAccess(id, request.user!);
      if (!access.ok) return reply.status(access.status).send({ success: false, error: access.error });

      const { status, severity } = request.query;
      const where: string[] = ['subscription_id = $1'];
      const params: unknown[] = [id];
      if (status && ['open', 'resolved', 'regressed', 'risk_accepted'].includes(status)) {
        params.push(status);
        where.push(`status = $${params.length}`);
      }
      if (severity && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity)) {
        params.push(severity);
        where.push(`severity = $${params.length}`);
      }
      const res = await query(
        `SELECT id, host_ip, finding_type, port_or_path, status, severity, cvss_score,
                title, description, first_seen_at, last_seen_at, resolved_at,
                risk_accepted_at, risk_accepted_reason, metadata
           FROM consolidated_findings
          WHERE ${where.join(' AND ')}
          ORDER BY
            CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                          WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
            first_seen_at DESC`,
        params,
      );
      const findings = res.rows.map((r: Record<string, unknown>) => ({
        id: r.id,
        hostIp: r.host_ip,
        findingType: r.finding_type,
        portOrPath: r.port_or_path,
        status: r.status,
        severity: r.severity,
        cvssScore: r.cvss_score != null ? Number(r.cvss_score) : null,
        title: r.title,
        description: r.description,
        firstSeenAt: r.first_seen_at,
        lastSeenAt: r.last_seen_at,
        resolvedAt: r.resolved_at,
        riskAcceptedAt: r.risk_accepted_at,
        riskAcceptedReason: r.risk_accepted_reason,
        metadata: r.metadata,
      }));
      return { success: true, data: { findings } };
    },
  );

  // POST /api/subscriptions/:id/findings/:fid/accept-risk
  server.post<{ Params: { id: string; fid: string }; Body: { reason?: string } }>(
    '/api/subscriptions/:id/findings/:fid/accept-risk',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, fid } = request.params;
      const access = await _checkSubscriptionAccess(id, request.user!);
      if (!access.ok) return reply.status(access.status).send({ success: false, error: access.error });
      if (!UUID_REGEX.test(fid)) {
        return reply.status(400).send({ success: false, error: 'Invalid finding ID' });
      }
      const reason = (request.body?.reason || '').trim();
      if (!reason || reason.length < 5) {
        return reply.status(400).send({ success: false, error: 'Begründung erforderlich (mind. 5 Zeichen).' });
      }
      const res = await query(
        `UPDATE consolidated_findings
            SET status = 'risk_accepted',
                risk_accepted_at = NOW(),
                risk_accepted_by = $1,
                risk_accepted_reason = $2,
                updated_at = NOW()
          WHERE id = $3 AND subscription_id = $4
          RETURNING id, status`,
        [request.user!.sub, reason, fid, id],
      );
      if (res.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Finding nicht gefunden.' });
      }
      audit({
        action: 'finding.accept_risk',
        details: { subscriptionId: id, findingId: fid, reason, userId: request.user!.sub },
        ip: request.ip,
      });
      return { success: true, data: { id: res.rows[0].id, status: res.rows[0].status } };
    },
  );

  // POST /api/subscriptions/:id/findings/:fid/reopen
  server.post<{ Params: { id: string; fid: string } }>(
    '/api/subscriptions/:id/findings/:fid/reopen',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, fid } = request.params;
      const access = await _checkSubscriptionAccess(id, request.user!);
      if (!access.ok) return reply.status(access.status).send({ success: false, error: access.error });
      if (!UUID_REGEX.test(fid)) {
        return reply.status(400).send({ success: false, error: 'Invalid finding ID' });
      }
      const res = await query(
        `UPDATE consolidated_findings
            SET status = 'open',
                risk_accepted_at = NULL,
                risk_accepted_by = NULL,
                risk_accepted_reason = NULL,
                updated_at = NOW()
          WHERE id = $1 AND subscription_id = $2 AND status = 'risk_accepted'
          RETURNING id, status`,
        [fid, id],
      );
      if (res.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Finding nicht gefunden oder nicht risk_accepted.' });
      }
      audit({
        action: 'finding.reopen',
        details: { subscriptionId: id, findingId: fid, userId: request.user!.sub },
        ip: request.ip,
      });
      return { success: true, data: { id: res.rows[0].id, status: res.rows[0].status } };
    },
  );

  // GET /api/subscriptions/:id/posture-history — Score-Verlauf
  server.get<{ Params: { id: string }; Querystring: { limit?: string } }>(
    '/api/subscriptions/:id/posture-history',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const access = await _checkSubscriptionAccess(id, request.user!);
      if (!access.ok) return reply.status(access.status).send({ success: false, error: access.error });
      const limit = Math.min(Math.max(Number(request.query.limit || 50), 1), 200);
      const res = await query(
        `SELECT id, triggering_order_id, snapshot_at, posture_score,
                severity_counts, new_findings, resolved_findings, regressed_findings
           FROM posture_history
          WHERE subscription_id = $1
          ORDER BY snapshot_at DESC
          LIMIT $2`,
        [id, limit],
      );
      const history = res.rows.map((r: Record<string, unknown>) => ({
        id: r.id,
        triggeringOrderId: r.triggering_order_id,
        snapshotAt: r.snapshot_at,
        postureScore: Number(r.posture_score),
        severityCounts: r.severity_counts,
        newFindings: Number(r.new_findings),
        resolvedFindings: Number(r.resolved_findings),
        regressedFindings: Number(r.regressed_findings),
      }));
      return { success: true, data: { history } };
    },
  );

  // POST /api/subscriptions/:id/status-report/generate — on-demand Status-PDF
  server.post<{ Params: { id: string } }>(
    '/api/subscriptions/:id/status-report/generate',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const access = await _checkSubscriptionAccess(id, request.user!);
      if (!access.ok) return reply.status(access.status).send({ success: false, error: access.error });

      // Enqueue Job an report-worker via Redis
      // TODO Phase 5: report-worker konsumiert "subscription-status-report"-Queue
      const { reportQueue } = await import('../lib/queue.js');
      await reportQueue.add('subscription-status-report', {
        subscriptionId: id,
        triggerReason: 'on_demand',
        requestedBy: request.user!.sub,
      });
      audit({
        action: 'subscription.status_report_requested',
        details: { subscriptionId: id, userId: request.user!.sub },
        ip: request.ip,
      });
      return {
        success: true,
        data: { message: 'Status-Report wird generiert. PDF erscheint in den naechsten 1-2 Min.' },
      };
    },
  );

  // GET /api/subscriptions/:id/status-reports — Liste der erzeugten PDFs
  server.get<{ Params: { id: string } }>(
    '/api/subscriptions/:id/status-reports',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const access = await _checkSubscriptionAccess(id, request.user!);
      if (!access.ok) return reply.status(access.status).send({ success: false, error: access.error });
      const res = await query(
        `SELECT id, period_start, period_end, trigger_reason, posture_score,
                findings_open, findings_resolved, findings_regressed,
                pdf_minio_key, pdf_size_bytes, generated_at
           FROM subscription_status_reports
          WHERE subscription_id = $1
          ORDER BY generated_at DESC`,
        [id],
      );
      return {
        success: true,
        data: {
          reports: res.rows.map((r: Record<string, unknown>) => ({
            id: r.id,
            periodStart: r.period_start,
            periodEnd: r.period_end,
            triggerReason: r.trigger_reason,
            postureScore: r.posture_score != null ? Number(r.posture_score) : null,
            findingsOpen: r.findings_open,
            findingsResolved: r.findings_resolved,
            findingsRegressed: r.findings_regressed,
            pdfMinioKey: r.pdf_minio_key,
            pdfSizeBytes: r.pdf_size_bytes,
            generatedAt: r.generated_at,
            downloadUrl: r.pdf_minio_key ? `/api/subscriptions/${id}/status-reports/${r.id}/download` : null,
          })),
        },
      };
    },
  );
}
