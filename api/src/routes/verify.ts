/**
 * Domain-Verifikation (optional im Multi-Target-Flow).
 *
 * Der Admin-Review-Flow ersetzt den alten Manual-Bypass. Die Verifikation
 * beschleunigt lediglich die Admin-Entscheidung bei FQDN-Targets und
 * speichert das Ergebnis im 90-Tage-Cache `verified_domains`.
 */
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { query } from '../lib/db.js';
import { verifyAll } from '../services/VerificationService.js';
import { audit } from '../lib/audit.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const FQDN_REGEX = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

interface CheckBody {
  targetId: string;
}

interface StatusParams {
  orderId: string;
}

export async function verifyRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/verify/check — verifiziert EIN scan_target (nur FQDN-Typen)
  server.post<{ Body: CheckBody }>(
    '/api/verify/check',
    async (request: FastifyRequest<{ Body: CheckBody }>, reply: FastifyReply) => {
      const { targetId } = request.body || ({} as CheckBody);
      if (!targetId || !UUID_REGEX.test(targetId)) {
        return reply.status(400).send({ success: false, error: 'Invalid or missing targetId' });
      }

      const result = await query<{
        id: string;
        canonical: string;
        target_type: string;
        order_id: string | null;
        subscription_id: string | null;
      }>(
        `SELECT id, canonical, target_type, order_id, subscription_id
         FROM scan_targets WHERE id = $1`,
        [targetId],
      );
      if (result.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Target nicht gefunden' });
      }

      const target = result.rows[0];
      if (target.target_type !== 'fqdn_root' && target.target_type !== 'fqdn_specific') {
        return reply.status(400).send({
          success: false,
          error: 'verification_not_applicable_for_ip_targets',
        });
      }
      if (!FQDN_REGEX.test(target.canonical)) {
        return reply.status(400).send({ success: false, error: 'invalid_fqdn' });
      }

      // Token wird ad-hoc generiert (nicht persistiert — Verifikation ist optional)
      const token = `vectiscan-${target.id}`;
      const verification = await verifyAll(target.canonical, token);

      if (verification.verified) {
        const customerRes = await query<{ customer_id: string }>(
          `SELECT COALESCE(o.customer_id, s.customer_id) AS customer_id
           FROM scan_targets t
           LEFT JOIN orders o ON o.id = t.order_id
           LEFT JOIN subscriptions s ON s.id = t.subscription_id
           WHERE t.id = $1`,
          [targetId],
        );
        const customerId = customerRes.rows[0]?.customer_id;
        if (customerId) {
          await query(
            `INSERT INTO verified_domains (customer_id, domain, verification_method)
             VALUES ($1, $2, $3)
             ON CONFLICT (customer_id, domain) DO UPDATE
             SET verification_method = EXCLUDED.verification_method,
                 verified_at = NOW(),
                 expires_at = NOW() + INTERVAL '90 days'`,
            [customerId, target.canonical, verification.method],
          );
        }

        audit({
          orderId: target.order_id,
          action: 'order.verified',
          details: { method: verification.method, targetId, fqdn: target.canonical },
          ip: request.ip,
        });
      }

      return reply.send({
        success: true,
        data: { verified: verification.verified, method: verification.method || null },
      });
    },
  );

  // GET /api/verify/status/:orderId — List der FQDN-Targets der Order + Verify-Status
  server.get<{ Params: StatusParams }>(
    '/api/verify/status/:orderId',
    async (request: FastifyRequest<{ Params: StatusParams }>, reply: FastifyReply) => {
      const { orderId } = request.params;
      if (!UUID_REGEX.test(orderId)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      const result = await query<{
        id: string; canonical: string; target_type: string;
        verified: boolean | null; method: string | null;
      }>(
        `SELECT t.id, t.canonical, t.target_type,
                (vd.id IS NOT NULL) AS verified, vd.verification_method AS method
         FROM scan_targets t
         LEFT JOIN orders o ON o.id = t.order_id
         LEFT JOIN verified_domains vd
                ON vd.customer_id = o.customer_id
               AND vd.domain = t.canonical
               AND vd.expires_at > NOW()
         WHERE t.order_id = $1
           AND t.target_type IN ('fqdn_root', 'fqdn_specific')`,
        [orderId],
      );

      return reply.send({
        success: true,
        data: { targets: result.rows },
      });
    },
  );
}
