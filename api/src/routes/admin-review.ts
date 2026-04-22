/**
 * Admin-Review-Endpoints fuer Multi-Target-Pre-Check.
 *
 * Ersetzt die alten subscription_domains-Review-Routen. Jedes Target kann
 * einzeln approved/rejected werden; Order-Release triggert Scan-Queue.
 */
import { FastifyInstance } from 'fastify';
import fastifyMultipart from '@fastify/multipart';
import { randomUUID } from 'crypto';
import { query } from '../lib/db.js';
import { scanQueue, publishEvent, enqueuePrecheck } from '../lib/queue.js';
import { minioClient } from '../lib/minio.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { audit } from '../lib/audit.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VALID_POLICIES = new Set(['enumerate', 'scoped', 'ip_only']);
const VALID_DOCUMENT_TYPES = new Set([
  'whois_screenshot', 'signed_authorization', 'email_thread',
  'scan_agreement', 'other',
]);
const AUTH_BUCKET = 'scan-authorizations';

export async function adminReviewRoutes(server: FastifyInstance): Promise<void> {
  await server.register(fastifyMultipart, { limits: { fileSize: 20 * 1024 * 1024 } });

  // GET /api/admin/review/queue — Orders + Subscriptions mit pending_target_review
  server.get(
    '/api/admin/review/queue',
    { preHandler: [requireAuth, requireAdmin] },
    async () => {
      const orders = await query(
        `SELECT o.id, o.target_url, o.package, o.target_count, o.live_hosts_count,
                o.created_at, c.email, c.company_name,
                COUNT(t.id)::int AS pending_targets
         FROM orders o
         JOIN customers c ON c.id = o.customer_id
         LEFT JOIN scan_targets t ON t.order_id = o.id
               AND t.status IN ('pending_review', 'precheck_complete', 'precheck_failed')
         WHERE o.status = 'pending_target_review'
         GROUP BY o.id, c.email, c.company_name
         ORDER BY o.created_at ASC`,
      );

      const subs = await query(
        `SELECT s.id, s.package, s.scan_interval, s.created_at,
                c.email, c.company_name,
                COUNT(t.id)::int AS pending_targets
         FROM subscriptions s
         JOIN customers c ON c.id = s.customer_id
         JOIN scan_targets t ON t.subscription_id = s.id
         WHERE t.status IN ('pending_review', 'precheck_complete', 'precheck_failed')
         GROUP BY s.id, c.email, c.company_name
         ORDER BY s.created_at ASC`,
      );

      return {
        success: true,
        data: {
          orders: (orders.rows as Array<Record<string, unknown>>).map(r => ({
            type: 'order',
            id: r.id,
            displayName: r.target_url,
            package: r.package,
            targetCount: r.target_count,
            liveHostsCount: r.live_hosts_count,
            pendingTargets: r.pending_targets,
            customer: { email: r.email, companyName: r.company_name },
            createdAt: r.created_at,
          })),
          subscriptions: (subs.rows as Array<Record<string, unknown>>).map(r => ({
            type: 'subscription',
            id: r.id,
            package: r.package,
            scanInterval: r.scan_interval,
            pendingTargets: r.pending_targets,
            customer: { email: r.email, companyName: r.company_name },
            createdAt: r.created_at,
          })),
        },
      };
    },
  );

  // GET /api/admin/review/:type/:id — Detail mit Pre-Check-Hosts und Authorizations
  server.get<{ Params: { type: string; id: string } }>(
    '/api/admin/review/:type/:id',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { type, id } = request.params;
      if (!['order', 'subscription'].includes(type) || !UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid type or ID' });
      }
      const filterCol = type === 'order' ? 'order_id' : 'subscription_id';

      const targets = await query(
        `SELECT id, raw_input, canonical, target_type, discovery_policy,
                exclusions, status, review_notes, approved_by, approved_at,
                created_at
         FROM scan_targets WHERE ${filterCol} = $1 ORDER BY created_at`,
        [id],
      );
      const hosts = await query(
        `SELECT scan_target_id, ip::text, fqdns, is_live, ports_hint,
                http_status, http_title, http_final_url, reverse_dns,
                cloud_provider, parking_page, source
         FROM scan_target_hosts
         WHERE scan_target_id = ANY($1)
         ORDER BY scan_target_id, ip`,
        [(targets.rows as Array<{ id: string }>).map(t => t.id)],
      );
      const auths = await query(
        `SELECT id, document_type, minio_path, original_filename,
                file_size_bytes, uploaded_by, notes, valid_until, created_at
         FROM scan_authorizations WHERE ${filterCol} = $1
         ORDER BY created_at DESC`,
        [id],
      );

      const hostsByTarget = new Map<string, Array<Record<string, unknown>>>();
      for (const h of hosts.rows as Array<Record<string, unknown>>) {
        const tid = h.scan_target_id as string;
        if (!hostsByTarget.has(tid)) hostsByTarget.set(tid, []);
        hostsByTarget.get(tid)!.push(h);
      }

      return {
        success: true,
        data: {
          type, id,
          targets: (targets.rows as Array<Record<string, unknown>>).map(t => ({
            id: t.id,
            raw_input: t.raw_input,
            canonical: t.canonical,
            target_type: t.target_type,
            discovery_policy: t.discovery_policy,
            exclusions: t.exclusions,
            status: t.status,
            review_notes: t.review_notes,
            approved_by: t.approved_by,
            approved_at: t.approved_at,
            hosts: hostsByTarget.get(t.id as string) || [],
          })),
          authorizations: auths.rows,
        },
      };
    },
  );

  // PUT /api/admin/targets/:targetId — update policy or exclusions before approve
  server.put<{ Params: { targetId: string }; Body: { discoveryPolicy?: string; exclusions?: unknown } }>(
    '/api/admin/targets/:targetId',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { targetId } = request.params;
      const body = request.body || {};
      if (!UUID_REGEX.test(targetId)) {
        return reply.status(400).send({ success: false, error: 'Invalid target ID' });
      }

      const updates: string[] = [];
      const params: unknown[] = [];
      if (body.discoveryPolicy) {
        if (!VALID_POLICIES.has(body.discoveryPolicy)) {
          return reply.status(400).send({ success: false, error: 'Invalid discoveryPolicy' });
        }
        params.push(body.discoveryPolicy);
        updates.push(`discovery_policy = $${params.length}`);
      }
      if (Array.isArray(body.exclusions)) {
        const cleaned = (body.exclusions as unknown[]).filter(e => typeof e === 'string') as string[];
        params.push(cleaned);
        updates.push(`exclusions = $${params.length}`);
      }
      if (updates.length === 0) {
        return reply.status(400).send({ success: false, error: 'No updates provided' });
      }

      params.push(targetId);
      const res = await query(
        `UPDATE scan_targets SET ${updates.join(', ')}, updated_at = NOW()
         WHERE id = $${params.length} RETURNING id, discovery_policy, exclusions`,
        params,
      );
      if (res.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Target nicht gefunden.' });
      }

      audit({ action: 'target.updated', details: { targetId, ...body } });
      return { success: true, data: res.rows[0] };
    },
  );

  // POST /api/admin/targets/:targetId/approve
  server.post<{ Params: { targetId: string }; Body: { discoveryPolicy?: string; exclusions?: unknown; notes?: string } }>(
    '/api/admin/targets/:targetId/approve',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const user = request.user!;
      const { targetId } = request.params;
      const body = request.body || {};
      if (!UUID_REGEX.test(targetId)) {
        return reply.status(400).send({ success: false, error: 'Invalid target ID' });
      }

      const sets: string[] = [
        "status = 'approved'",
        'approved_by = $1',
        'approved_at = NOW()',
        'updated_at = NOW()',
      ];
      const params: unknown[] = [user.sub];
      if (body.discoveryPolicy && VALID_POLICIES.has(body.discoveryPolicy)) {
        params.push(body.discoveryPolicy);
        sets.push(`discovery_policy = $${params.length}`);
      }
      if (Array.isArray(body.exclusions)) {
        const cleaned = (body.exclusions as unknown[]).filter(e => typeof e === 'string') as string[];
        params.push(cleaned);
        sets.push(`exclusions = $${params.length}`);
      }
      if (body.notes !== undefined) {
        params.push(body.notes);
        sets.push(`review_notes = $${params.length}`);
      }
      params.push(targetId);

      const res = await query(
        `UPDATE scan_targets SET ${sets.join(', ')}
         WHERE id = $${params.length}
         RETURNING id, order_id, subscription_id, raw_input`,
        params,
      );
      if (res.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Target nicht gefunden.' });
      }
      const row = res.rows[0] as Record<string, unknown>;

      audit({
        orderId: (row.order_id as string) || null,
        action: 'target.approved',
        details: { targetId, raw: row.raw_input, approvedBy: user.sub },
        ip: request.ip,
      });

      if (row.order_id) {
        publishEvent(row.order_id as string, {
          type: 'target_approved', orderId: row.order_id, targetId,
        });
      }

      return { success: true, data: { id: row.id, status: 'approved' } };
    },
  );

  // POST /api/admin/targets/:targetId/reject
  server.post<{ Params: { targetId: string }; Body: { reason?: string } }>(
    '/api/admin/targets/:targetId/reject',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const user = request.user!;
      const { targetId } = request.params;
      const reason = request.body?.reason || '';
      if (!UUID_REGEX.test(targetId)) {
        return reply.status(400).send({ success: false, error: 'Invalid target ID' });
      }

      const res = await query(
        `UPDATE scan_targets SET status = 'rejected', review_notes = $1,
               approved_by = $2, approved_at = NOW(), updated_at = NOW()
         WHERE id = $3
         RETURNING id, order_id, subscription_id, raw_input`,
        [reason, user.sub, targetId],
      );
      if (res.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Target nicht gefunden.' });
      }
      const row = res.rows[0] as Record<string, unknown>;

      audit({
        orderId: (row.order_id as string) || null,
        action: 'target.rejected',
        details: { targetId, raw: row.raw_input, reason, rejectedBy: user.sub },
        ip: request.ip,
      });

      if (row.order_id) {
        publishEvent(row.order_id as string, {
          type: 'target_rejected', orderId: row.order_id, targetId, reason,
        });
      }

      return { success: true, data: { id: row.id, status: 'rejected' } };
    },
  );

  // POST /api/admin/orders/:id/release — start scan after all targets decided
  server.post<{ Params: { id: string } }>(
    '/api/admin/orders/:id/release',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID' });
      }

      const order = await query<{ id: string; status: string; package: string }>(
        'SELECT id, status, package FROM orders WHERE id = $1',
        [id],
      );
      if (order.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order nicht gefunden.' });
      }
      if (order.rows[0].status !== 'pending_target_review') {
        return reply.status(409).send({ success: false, error: `Order-Status ${order.rows[0].status} erlaubt kein Release.` });
      }

      const pending = await query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM scan_targets
         WHERE order_id = $1
           AND status NOT IN ('approved', 'rejected', 'removed')`,
        [id],
      );
      if (parseInt(pending.rows[0].count, 10) > 0) {
        return reply.status(409).send({ success: false, error: 'Noch nicht alle Targets entschieden.' });
      }

      const approved = await query(
        `SELECT id, discovery_policy, exclusions FROM scan_targets
         WHERE order_id = $1 AND status = 'approved'`,
        [id],
      );
      if (approved.rows.length === 0) {
        return reply.status(409).send({ success: false, error: 'Kein einziges Target freigegeben.' });
      }

      for (const t of approved.rows as Array<Record<string, unknown>>) {
        await query(
          `INSERT INTO scan_run_targets
             (order_id, scan_target_id, in_scope, snapshot_discovery_policy, snapshot_exclusions)
           VALUES ($1, $2, true, $3, $4)
           ON CONFLICT (order_id, scan_target_id) DO UPDATE
             SET snapshot_discovery_policy = EXCLUDED.snapshot_discovery_policy,
                 snapshot_exclusions = EXCLUDED.snapshot_exclusions`,
          [id, t.id, t.discovery_policy, t.exclusions],
        );
      }

      // Rejected/Removed als out-of-scope anlegen (historisch korrekt)
      const skipped = await query(
        `SELECT id, status FROM scan_targets
         WHERE order_id = $1 AND status IN ('rejected', 'removed')`,
        [id],
      );
      for (const t of skipped.rows as Array<Record<string, unknown>>) {
        const reason = t.status === 'rejected' ? 'rejected_by_admin' : 'removed_by_admin';
        await query(
          `INSERT INTO scan_run_targets
             (order_id, scan_target_id, in_scope, out_of_scope_reason,
              snapshot_discovery_policy, snapshot_exclusions)
           VALUES ($1, $2, false, $3, 'scoped', '{}')
           ON CONFLICT (order_id, scan_target_id) DO NOTHING`,
          [id, t.id, reason],
        );
      }

      await query("UPDATE orders SET status = 'queued', updated_at = NOW() WHERE id = $1", [id]);
      await scanQueue.add('scan', { orderId: id, package: order.rows[0].package });
      await publishEvent(id, { type: 'status', orderId: id, status: 'queued' });

      audit({ orderId: id, action: 'order.released', details: { approvedCount: approved.rows.length }, ip: request.ip });

      return { success: true, data: { orderId: id, approvedCount: approved.rows.length } };
    },
  );

  // POST /api/admin/orders/:id/authorizations — multipart upload
  server.post<{ Params: { id: string } }>(
    '/api/admin/orders/:id/authorizations',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const user = request.user!;
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID' });
      }

      const data = await request.file();
      if (!data) {
        return reply.status(400).send({ success: false, error: 'Datei fehlt.' });
      }
      const fields = data.fields as Record<string, { value?: string }>;
      const docType = (fields?.document_type?.value || 'other');
      if (!VALID_DOCUMENT_TYPES.has(docType)) {
        return reply.status(400).send({ success: false, error: 'Invalid document_type' });
      }

      const notes = fields?.notes?.value || null;
      const validUntil = fields?.valid_until?.value || null;
      const objectName = `${id}/${randomUUID()}-${data.filename}`;
      const buffer = await data.toBuffer();

      await minioClient.putObject(AUTH_BUCKET, objectName, buffer, buffer.length, {
        'Content-Type': data.mimetype,
      });

      const ins = await query<{ id: string }>(
        `INSERT INTO scan_authorizations
           (order_id, document_type, minio_path, original_filename,
            file_size_bytes, uploaded_by, notes, valid_until)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id`,
        [id, docType, objectName, data.filename, buffer.length, user.sub, notes, validUntil],
      );

      audit({
        orderId: id, action: 'authorization.uploaded',
        details: { authId: ins.rows[0].id, docType, filename: data.filename, size: buffer.length },
      });

      return reply.status(201).send({
        success: true,
        data: { id: ins.rows[0].id, minio_path: objectName, filename: data.filename },
      });
    },
  );

  // POST /api/admin/subscriptions/:id/authorizations — multipart upload
  server.post<{ Params: { id: string } }>(
    '/api/admin/subscriptions/:id/authorizations',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const user = request.user!;
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid subscription ID' });
      }

      const data = await request.file();
      if (!data) {
        return reply.status(400).send({ success: false, error: 'Datei fehlt.' });
      }
      const fields = data.fields as Record<string, { value?: string }>;
      const docType = (fields?.document_type?.value || 'other');
      if (!VALID_DOCUMENT_TYPES.has(docType)) {
        return reply.status(400).send({ success: false, error: 'Invalid document_type' });
      }

      const notes = fields?.notes?.value || null;
      const validUntil = fields?.valid_until?.value || null;
      const objectName = `sub-${id}/${randomUUID()}-${data.filename}`;
      const buffer = await data.toBuffer();

      await minioClient.putObject(AUTH_BUCKET, objectName, buffer, buffer.length, {
        'Content-Type': data.mimetype,
      });

      const ins = await query<{ id: string }>(
        `INSERT INTO scan_authorizations
           (subscription_id, document_type, minio_path, original_filename,
            file_size_bytes, uploaded_by, notes, valid_until)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id`,
        [id, docType, objectName, data.filename, buffer.length, user.sub, notes, validUntil],
      );

      audit({
        action: 'authorization.uploaded',
        details: { subscriptionId: id, authId: ins.rows[0].id, docType, filename: data.filename },
      });

      return reply.status(201).send({
        success: true,
        data: { id: ins.rows[0].id, minio_path: objectName, filename: data.filename },
      });
    },
  );

  // DELETE /api/admin/authorizations/:id
  server.delete<{ Params: { id: string } }>(
    '/api/admin/authorizations/:id',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid ID' });
      }

      const res = await query<{ minio_path: string }>(
        'DELETE FROM scan_authorizations WHERE id = $1 RETURNING minio_path',
        [id],
      );
      if (res.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Authorization nicht gefunden.' });
      }

      try {
        await minioClient.removeObject(AUTH_BUCKET, res.rows[0].minio_path);
      } catch (err) {
        request.log.warn({ err, id }, 'Could not delete MinIO object (already gone?)');
      }

      audit({ action: 'authorization.deleted', details: { authId: id } });
      return { success: true, data: { message: 'Authorization entfernt.' } };
    },
  );

  // POST /api/admin/targets/:targetId/restart-precheck — Admin kann Pre-Check erneut auslösen
  server.post<{ Params: { targetId: string } }>(
    '/api/admin/targets/:targetId/restart-precheck',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { targetId } = request.params;
      if (!UUID_REGEX.test(targetId)) {
        return reply.status(400).send({ success: false, error: 'Invalid target ID' });
      }

      const res = await query<{ id: string; order_id: string | null; subscription_id: string | null }>(
        `UPDATE scan_targets SET status = 'pending_precheck', updated_at = NOW()
         WHERE id = $1
         RETURNING id, order_id, subscription_id`,
        [targetId],
      );
      if (res.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Target nicht gefunden.' });
      }

      // Alte Hosts-Eintraege verwerfen
      await query('DELETE FROM scan_target_hosts WHERE scan_target_id = $1', [targetId]);

      const row = res.rows[0];
      if (row.order_id) {
        await enqueuePrecheck({ orderId: row.order_id, targetIds: [targetId] });
      } else if (row.subscription_id) {
        await enqueuePrecheck({ subscriptionId: row.subscription_id, targetIds: [targetId] });
      }

      return { success: true, data: { targetId, status: 'pending_precheck' } };
    },
  );
}
