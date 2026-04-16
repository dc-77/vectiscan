/**
 * Subscription management routes.
 *
 * Customers can create subscriptions (payment mocked for now — Stripe later).
 * Customers can request domain additions (pending admin approval).
 * Admins can approve/reject domains, manage subscriptions.
 */
import { FastifyInstance } from 'fastify';
import { query } from '../lib/db.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { audit } from '../lib/audit.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function subscriptionRoutes(server: FastifyInstance): Promise<void> {

  // ── Customer Endpoints ──────────────────────────────────

  // POST /api/subscriptions — create a new subscription (payment mocked)
  server.post('/api/subscriptions', { preHandler: [requireAuth] }, async (request, reply) => {
    const user = request.user!;
    const body = request.body as Record<string, unknown> | null;

    const pkg = (body?.package as string || 'perimeter').toLowerCase();
    const validPackages = ['perimeter', 'insurance', 'compliance', 'supplychain', 'webcheck'];
    if (!validPackages.includes(pkg)) {
      return reply.status(400).send({ success: false, error: `Ungültiges Paket: ${pkg}` });
    }

    const scanInterval = (body?.scanInterval as string || 'monthly').toLowerCase();
    if (!['weekly', 'monthly', 'quarterly'].includes(scanInterval)) {
      return reply.status(400).send({ success: false, error: 'Ungültiges Intervall. Erlaubt: weekly, monthly, quarterly' });
    }

    const domains = (body?.domains as string[]) || [];
    if (domains.length === 0) {
      return reply.status(400).send({ success: false, error: 'Mindestens eine Domain erforderlich.' });
    }
    if (domains.length > 5) {
      return reply.status(400).send({ success: false, error: 'Maximal 5 Domains pro Abo.' });
    }

    const reportEmails = (body?.reportEmails as string[]) || [user.email];

    // Resolve customer_id (same logic as order creation)
    let customerId = user.customerId;
    if (!customerId) {
      const custResult = await query<{ id: string }>(
        'INSERT INTO customers (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id',
        [user.email],
      );
      customerId = custResult.rows[0].id;
    }

    // TODO: Stripe integration — create checkout session, set status to 'pending'
    // For now: subscription goes active immediately (payment mocked)
    const now = new Date();
    const expiresAt = new Date(now);
    expiresAt.setFullYear(expiresAt.getFullYear() + 1);

    // Create subscription
    const subResult = await query<{ id: string }>(
      `INSERT INTO subscriptions (customer_id, package, status, scan_interval, report_emails,
       started_at, expires_at, amount_cents)
       VALUES ($1, $2, 'active', $3, $4, NOW(), $5, 0)
       RETURNING id`,
      [customerId, pkg, scanInterval, reportEmails, expiresAt.toISOString()],
    );
    const subscriptionId = subResult.rows[0].id;

    // Add domains (pending admin approval)
    for (const domain of domains) {
      const cleanDomain = domain.toLowerCase().trim();
      if (!cleanDomain) continue;
      await query(
        `INSERT INTO subscription_domains (subscription_id, domain, status)
         VALUES ($1, $2, 'pending_approval')
         ON CONFLICT (subscription_id, domain) DO NOTHING`,
        [subscriptionId, cleanDomain],
      );
    }

    audit({
      action: 'subscription.created',
      details: { subscriptionId, package: pkg, domains, scanInterval, userId: user.sub },
      ip: request.ip,
    });

    return {
      success: true,
      data: {
        id: subscriptionId,
        package: pkg,
        status: 'active',
        scanInterval,
        domains: domains.map(d => ({ domain: d.toLowerCase().trim(), status: 'pending_approval' })),
        expiresAt: expiresAt.toISOString(),
        message: 'Abo erstellt. Domains warten auf Admin-Freigabe.',
      },
    };
  });

  // GET /api/subscriptions — list customer's subscriptions
  server.get('/api/subscriptions', { preHandler: [requireAuth] }, async (request) => {
    const user = request.user!;

    // Resolve customer_id
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
      const domainsResult = await query(
        'SELECT id, domain, status, verified_at, enabled FROM subscription_domains WHERE subscription_id = $1 ORDER BY domain',
        [sub.id],
      );
      subscriptions.push({
        id: sub.id,
        customerEmail: sub.customer_email,
        package: sub.package,
        status: sub.status,
        scanInterval: sub.scan_interval,
        maxDomains: sub.max_domains,
        maxRescans: sub.max_rescans,
        rescansUsed: sub.rescans_used,
        reportEmails: sub.report_emails,
        startedAt: sub.started_at,
        expiresAt: sub.expires_at,
        lastScanAt: sub.last_scan_at,
        createdAt: sub.created_at,
        domains: (domainsResult.rows as Array<Record<string, unknown>>).map(d => ({
          id: d.id,
          domain: d.domain,
          status: d.status,
          verifiedAt: d.verified_at,
          enabled: d.enabled,
        })),
      });
    }

    return { success: true, data: { subscriptions } };
  });

  // POST /api/subscriptions/:id/domains — customer requests domain addition
  server.post<{ Params: { id: string } }>(
    '/api/subscriptions/:id/domains',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;
      const body = request.body as Record<string, unknown> | null;
      const domain = (body?.domain as string || '').toLowerCase().trim();

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid subscription ID' });
      }
      if (!domain) {
        return reply.status(400).send({ success: false, error: 'Domain erforderlich.' });
      }

      // Check ownership + domain count
      const sub = await query(
        'SELECT customer_id, max_domains FROM subscriptions WHERE id = $1',
        [id],
      );
      if (sub.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Abo nicht gefunden.' });
      }

      const subRow = sub.rows[0] as Record<string, unknown>;
      // Resolve customer_id for admin users
      let customerId = user.customerId;
      if (!customerId) {
        const custResult = await query<{ id: string }>('SELECT id FROM customers WHERE email = $1', [user.email]);
        if (custResult.rows.length > 0) customerId = custResult.rows[0].id;
      }

      if (user.role !== 'admin' && subRow.customer_id !== customerId) {
        return reply.status(403).send({ success: false, error: 'Zugriff verweigert.' });
      }

      const domainCount = await query(
        'SELECT COUNT(*)::int AS count FROM subscription_domains WHERE subscription_id = $1',
        [id],
      );
      if ((domainCount.rows[0] as Record<string, unknown>).count as number >= (subRow.max_domains as number)) {
        return reply.status(409).send({ success: false, error: `Maximale Domainanzahl (${subRow.max_domains}) erreicht.` });
      }

      await query(
        `INSERT INTO subscription_domains (subscription_id, domain, status)
         VALUES ($1, $2, 'pending_approval')
         ON CONFLICT (subscription_id, domain) DO NOTHING`,
        [id, domain],
      );

      audit({
        action: 'subscription.domain_requested',
        details: { subscriptionId: id, domain, userId: user.sub },
        ip: request.ip,
      });

      return { success: true, data: { domain, status: 'pending_approval' } };
    },
  );

  // POST /api/subscriptions/:id/rescan — customer requests a re-scan
  server.post<{ Params: { id: string } }>(
    '/api/subscriptions/:id/rescan',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;
      const body = request.body as Record<string, unknown> | null;
      const domain = (body?.domain as string || '').toLowerCase().trim();

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

      if ((subRow.rescans_used as number) >= (subRow.max_rescans as number)) {
        return reply.status(409).send({
          success: false,
          error: `Re-Scan-Kontingent erschöpft (${subRow.rescans_used}/${subRow.max_rescans}).`,
        });
      }

      // Verify domain belongs to subscription and is verified
      const domainCheck = await query(
        `SELECT domain FROM subscription_domains
         WHERE subscription_id = $1 AND domain = $2 AND status = 'verified' AND enabled = true`,
        [id, domain],
      );
      if (domainCheck.rows.length === 0) {
        return reply.status(400).send({ success: false, error: 'Domain nicht verifiziert oder nicht im Abo.' });
      }

      // Resolve customer_id
      let customerId = user.customerId;
      if (!customerId) {
        const custResult = await query<{ id: string }>('SELECT id FROM customers WHERE email = $1', [user.email]);
        if (custResult.rows.length > 0) customerId = custResult.rows[0].id;
      }

      // Create re-scan order
      const orderResult = await query<{ id: string }>(
        `INSERT INTO orders (customer_id, target_url, package, status, verified_at, subscription_id, is_rescan)
         VALUES ($1, $2, $3, 'queued', NOW(), $4, true)
         RETURNING id`,
        [customerId, domain, subRow.package, id],
      );
      const orderId = orderResult.rows[0].id;

      // Increment rescan counter
      await query(
        'UPDATE subscriptions SET rescans_used = rescans_used + 1, updated_at = NOW() WHERE id = $1',
        [id],
      );

      // Enqueue scan
      const { scanQueue: sq, publishEvent: pub } = await import('../lib/queue.js');
      await sq.add('scan', { orderId, targetDomain: domain, package: subRow.package });
      await pub(orderId, { type: 'status', orderId, status: 'queued' });

      audit({
        action: 'subscription.rescan',
        details: { subscriptionId: id, domain, orderId, userId: user.sub },
        ip: request.ip,
      });

      return { success: true, data: { orderId, message: 'Re-Scan gestartet.' } };
    },
  );

  // ── Admin Endpoints ──────────────────────────────────

  // POST /api/admin/subscription-domains/:id/approve — approve a domain
  server.post<{ Params: { id: string } }>(
    '/api/admin/subscription-domains/:id/approve',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid domain ID' });
      }

      const result = await query(
        `UPDATE subscription_domains SET status = 'verified', verified_at = NOW()
         WHERE id = $1 AND status = 'pending_approval'
         RETURNING domain, subscription_id`,
        [id],
      );

      if (result.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Domain nicht gefunden oder bereits genehmigt.' });
      }

      const row = result.rows[0] as Record<string, unknown>;
      audit({
        action: 'subscription.domain_approved',
        details: { domainId: id, domain: row.domain, subscriptionId: row.subscription_id },
        ip: request.ip,
      });

      return { success: true, data: { message: `Domain ${row.domain} genehmigt.` } };
    },
  );

  // POST /api/admin/subscription-domains/:id/reject — reject a domain
  server.post<{ Params: { id: string } }>(
    '/api/admin/subscription-domains/:id/reject',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid domain ID' });
      }

      const result = await query(
        `UPDATE subscription_domains SET status = 'rejected'
         WHERE id = $1 AND status = 'pending_approval'
         RETURNING domain, subscription_id`,
        [id],
      );

      if (result.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Domain nicht gefunden oder bereits bearbeitet.' });
      }

      const row = result.rows[0] as Record<string, unknown>;
      audit({
        action: 'subscription.domain_rejected',
        details: { domainId: id, domain: row.domain, subscriptionId: row.subscription_id },
        ip: request.ip,
      });

      return { success: true, data: { message: `Domain ${row.domain} abgelehnt.` } };
    },
  );

  // GET /api/admin/pending-domains — list domains awaiting approval
  server.get('/api/admin/pending-domains', { preHandler: [requireAuth, requireAdmin] }, async () => {
    const result = await query(
      `SELECT sd.id, sd.domain, sd.created_at, sd.subscription_id,
              s.package, c.email AS customer_email
       FROM subscription_domains sd
       JOIN subscriptions s ON s.id = sd.subscription_id
       JOIN customers c ON c.id = s.customer_id
       WHERE sd.status = 'pending_approval'
       ORDER BY sd.created_at ASC`,
    );

    return {
      success: true,
      data: {
        domains: (result.rows as Array<Record<string, unknown>>).map(r => ({
          id: r.id,
          domain: r.domain,
          subscriptionId: r.subscription_id,
          package: r.package,
          customerEmail: r.customer_email,
          createdAt: r.created_at,
        })),
      },
    };
  });
}
