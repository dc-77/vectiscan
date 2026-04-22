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
}
