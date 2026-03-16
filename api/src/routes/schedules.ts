/**
 * Scan Schedule routes — CRUD for recurring/scheduled scans.
 */
import { FastifyInstance } from 'fastify';
import { query } from '../lib/db.js';
import { requireAuth } from './auth.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DOMAIN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const SCHEDULE_TYPES = ['weekly', 'monthly', 'quarterly', 'once'] as const;
const PACKAGES = ['basic', 'professional', 'nis2'] as const;

const SCHEDULE_LABELS: Record<string, string> = {
  weekly: 'Wöchentlich',
  monthly: 'Monatlich',
  quarterly: 'Quartalsweise',
  once: 'Einmalig',
};

function calculateNextScanAt(scheduleType: string, scheduledAt?: string): Date {
  if (scheduleType === 'once' && scheduledAt) {
    return new Date(scheduledAt);
  }
  const now = new Date();
  switch (scheduleType) {
    case 'weekly':
      now.setDate(now.getDate() + 7);
      return now;
    case 'monthly':
      now.setMonth(now.getMonth() + 1);
      return now;
    case 'quarterly':
      now.setMonth(now.getMonth() + 3);
      return now;
    default:
      now.setDate(now.getDate() + 7);
      return now;
  }
}

interface ScheduleParams { id: string }

export async function scheduleRoutes(server: FastifyInstance): Promise<void> {

  // GET /api/schedules — list all schedules for the authenticated customer
  server.get('/api/schedules', { preHandler: [requireAuth] }, async (request) => {
    const user = request.user!;
    const isAdmin = user.role === 'admin';

    const result = await query(
      `SELECT s.id, s.target_url, s.package, s.schedule_type, s.scheduled_at,
              s.enabled, s.last_scan_at, s.next_scan_at, s.last_order_id, s.created_at
       FROM scan_schedules s
       ${isAdmin ? '' : 'WHERE s.customer_id = $1'}
       ORDER BY s.created_at DESC`,
      isAdmin ? [] : [user.customerId],
    );

    const schedules = result.rows.map((row: Record<string, unknown>) => ({
      id: row.id,
      domain: row.target_url,
      package: row.package,
      scheduleType: row.schedule_type,
      scheduleLabel: SCHEDULE_LABELS[row.schedule_type as string] || row.schedule_type,
      scheduledAt: row.scheduled_at ? (row.scheduled_at as Date).toISOString() : null,
      enabled: row.enabled,
      lastScanAt: row.last_scan_at ? (row.last_scan_at as Date).toISOString() : null,
      nextScanAt: (row.next_scan_at as Date).toISOString(),
      lastOrderId: row.last_order_id || null,
      createdAt: (row.created_at as Date).toISOString(),
    }));

    return { success: true, data: { schedules } };
  });

  // POST /api/schedules — create a new schedule
  server.post('/api/schedules', { preHandler: [requireAuth] }, async (request, reply) => {
    const user = request.user!;
    const body = request.body as Record<string, unknown>;

    const domain = ((body.domain as string) || '').trim().toLowerCase()
      .replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/\.$/, '');
    const pkg = (body.package as string) || 'professional';
    const scheduleType = (body.scheduleType as string) || 'monthly';
    const scheduledAt = body.scheduledAt as string | undefined;

    // Validate
    if (!DOMAIN_REGEX.test(domain)) {
      return reply.status(400).send({ success: false, error: 'Ungültige Domain' });
    }
    if (!PACKAGES.includes(pkg as typeof PACKAGES[number])) {
      return reply.status(400).send({ success: false, error: 'Ungültiges Paket' });
    }
    if (!SCHEDULE_TYPES.includes(scheduleType as typeof SCHEDULE_TYPES[number])) {
      return reply.status(400).send({ success: false, error: 'Ungültiger Zeitplan-Typ' });
    }
    if (scheduleType === 'once' && !scheduledAt) {
      return reply.status(400).send({ success: false, error: 'Einmalige Scans benötigen einen Zeitpunkt (scheduledAt)' });
    }

    // Check: domain must have been verified by this customer before
    const verified = await query(
      `SELECT id FROM orders
       WHERE customer_id = $1 AND target_url = $2 AND verified_at IS NOT NULL
       LIMIT 1`,
      [user.customerId, domain],
    );
    if (verified.rows.length === 0) {
      return reply.status(400).send({
        success: false,
        error: 'Diese Domain wurde noch nicht verifiziert. Bitte zuerst einen normalen Scan starten und die Domain verifizieren.',
      });
    }

    const nextScanAt = calculateNextScanAt(scheduleType, scheduledAt);

    const result = await query(
      `INSERT INTO scan_schedules (customer_id, target_url, package, schedule_type, scheduled_at, next_scan_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      [user.customerId, domain, pkg, scheduleType, scheduledAt || null, nextScanAt.toISOString()],
    );

    return reply.status(201).send({
      success: true,
      data: { id: (result.rows[0] as Record<string, unknown>).id },
    });
  });

  // GET /api/schedules/:id — schedule details + recent orders
  server.get<{ Params: ScheduleParams }>('/api/schedules/:id', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid schedule ID' });
    }

    const result = await query(
      `SELECT s.*, c.email FROM scan_schedules s
       JOIN customers c ON s.customer_id = c.id
       WHERE s.id = $1`,
      [id],
    );
    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Schedule not found' });
    }
    const s = result.rows[0] as Record<string, unknown>;
    if (user.role !== 'admin' && s.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Recent orders for this domain by this customer
    const orders = await query(
      `SELECT id, status, scan_started_at, scan_finished_at, created_at
       FROM orders WHERE customer_id = $1 AND target_url = $2
       ORDER BY created_at DESC LIMIT 10`,
      [s.customer_id, s.target_url],
    );

    return {
      success: true,
      data: {
        schedule: {
          id: s.id,
          domain: s.target_url,
          package: s.package,
          scheduleType: s.schedule_type,
          scheduleLabel: SCHEDULE_LABELS[s.schedule_type as string] || s.schedule_type,
          scheduledAt: s.scheduled_at ? (s.scheduled_at as Date).toISOString() : null,
          enabled: s.enabled,
          lastScanAt: s.last_scan_at ? (s.last_scan_at as Date).toISOString() : null,
          nextScanAt: (s.next_scan_at as Date).toISOString(),
          lastOrderId: s.last_order_id || null,
          createdAt: (s.created_at as Date).toISOString(),
        },
        recentOrders: orders.rows.map((o: Record<string, unknown>) => ({
          id: o.id,
          status: o.status,
          startedAt: o.scan_started_at ? (o.scan_started_at as Date).toISOString() : null,
          finishedAt: o.scan_finished_at ? (o.scan_finished_at as Date).toISOString() : null,
          createdAt: (o.created_at as Date).toISOString(),
        })),
      },
    };
  });

  // PUT /api/schedules/:id — update schedule
  server.put<{ Params: ScheduleParams }>('/api/schedules/:id', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;
    const body = request.body as Record<string, unknown>;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid schedule ID' });
    }

    // Ownership check
    const check = await query('SELECT customer_id FROM scan_schedules WHERE id = $1', [id]);
    if (check.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Schedule not found' });
    }
    if (user.role !== 'admin' && (check.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    const updates: string[] = [];
    const values: unknown[] = [];
    let paramIdx = 1;

    if (body.package !== undefined) {
      if (!PACKAGES.includes(body.package as typeof PACKAGES[number])) {
        return reply.status(400).send({ success: false, error: 'Ungültiges Paket' });
      }
      updates.push(`package = $${paramIdx++}`);
      values.push(body.package);
    }
    if (body.scheduleType !== undefined) {
      if (!SCHEDULE_TYPES.includes(body.scheduleType as typeof SCHEDULE_TYPES[number])) {
        return reply.status(400).send({ success: false, error: 'Ungültiger Zeitplan-Typ' });
      }
      updates.push(`schedule_type = $${paramIdx++}`);
      values.push(body.scheduleType);

      const nextAt = calculateNextScanAt(body.scheduleType as string, body.scheduledAt as string);
      updates.push(`next_scan_at = $${paramIdx++}`);
      values.push(nextAt.toISOString());

      if (body.scheduledAt) {
        updates.push(`scheduled_at = $${paramIdx++}`);
        values.push(body.scheduledAt);
      }
    }
    if (body.enabled !== undefined) {
      updates.push(`enabled = $${paramIdx++}`);
      values.push(body.enabled);
    }

    if (updates.length === 0) {
      return reply.status(400).send({ success: false, error: 'Keine Änderungen' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(id);

    await query(
      `UPDATE scan_schedules SET ${updates.join(', ')} WHERE id = $${paramIdx}`,
      values,
    );

    return { success: true };
  });

  // DELETE /api/schedules/:id
  server.delete<{ Params: ScheduleParams }>('/api/schedules/:id', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid schedule ID' });
    }

    const check = await query('SELECT customer_id FROM scan_schedules WHERE id = $1', [id]);
    if (check.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Schedule not found' });
    }
    if (user.role !== 'admin' && (check.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    await query('DELETE FROM scan_schedules WHERE id = $1', [id]);
    return { success: true };
  });
}
