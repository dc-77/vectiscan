import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { query } from '../lib/db.js';
import { scanQueue, publishEvent } from '../lib/queue.js';
import { verifyAll } from '../services/VerificationService.js';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface CheckBody {
  orderId: string;
}

interface StatusParams {
  orderId: string;
}

export async function verifyRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/verify/check
  server.post<{ Body: CheckBody }>('/api/verify/check', async (request: FastifyRequest<{ Body: CheckBody }>, reply: FastifyReply) => {
    const { orderId } = request.body || {};

    if (!orderId || !UUID_REGEX.test(orderId)) {
      return reply.status(400).send({ success: false, error: 'Invalid or missing orderId' });
    }

    const result = await query<{
      id: string;
      target_url: string;
      verification_token: string;
      status: string;
      package: string;
      verified_at: Date | null;
      verification_method: string | null;
    }>(
      'SELECT id, target_url, verification_token, status, package, verified_at, verification_method FROM orders WHERE id = $1',
      [orderId],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order nicht gefunden' });
    }

    const order = result.rows[0];

    // Idempotent: already verified
    if (order.verified_at) {
      return reply.send({
        success: true,
        data: { verified: true, method: order.verification_method },
      });
    }

    const domain = order.target_url;
    const token = order.verification_token;

    const verification = await verifyAll(domain, token);

    if (verification.verified) {
      await query(
        "UPDATE orders SET status = 'queued', verified_at = NOW(), verification_method = $1 WHERE id = $2",
        [verification.method, orderId],
      );

      await query(
        'INSERT INTO audit_log (order_id, action, details, ip_address) VALUES ($1, $2, $3, $4)',
        [orderId, 'verification_success', JSON.stringify({ method: verification.method }), request.ip],
      );

      // Prototyp: Scan direkt starten (kein Zahlungsflow)
      await scanQueue.add('scan', {
        orderId,
        targetDomain: order.target_url,
        package: order.package,
      });

      await publishEvent(orderId, { type: 'status', orderId, status: 'queued' });

      return reply.send({
        success: true,
        data: { verified: true, method: verification.method },
      });
    }

    return reply.send({
      success: true,
      data: { verified: false },
    });
  });

  // POST /api/verify/manual — Skip verification (prototype only)
  server.post<{ Body: CheckBody }>('/api/verify/manual', async (request: FastifyRequest<{ Body: CheckBody }>, reply: FastifyReply) => {
    const { orderId } = request.body || {};

    if (!orderId || !UUID_REGEX.test(orderId)) {
      return reply.status(400).send({ success: false, error: 'Invalid or missing orderId' });
    }

    const result = await query<{
      id: string;
      target_url: string;
      status: string;
      package: string;
      verified_at: Date | null;
    }>(
      'SELECT id, target_url, status, package, verified_at FROM orders WHERE id = $1',
      [orderId],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order nicht gefunden' });
    }

    const order = result.rows[0];

    if (order.verified_at) {
      return reply.send({ success: true, data: { verified: true, method: 'manual' } });
    }

    await query(
      "UPDATE orders SET status = 'queued', verified_at = NOW(), verification_method = 'manual' WHERE id = $1",
      [orderId],
    );

    await query(
      'INSERT INTO audit_log (order_id, action, details, ip_address) VALUES ($1, $2, $3, $4)',
      [orderId, 'manual_verification', '{"method":"manual"}', request.ip],
    );

    await scanQueue.add('scan', {
      orderId,
      targetDomain: order.target_url,
      package: order.package,
    });

    await publishEvent(orderId, { type: 'status', orderId, status: 'queued' });

    return reply.send({ success: true, data: { verified: true, method: 'manual' } });
  });

  // GET /api/verify/status/:orderId
  server.get<{ Params: StatusParams }>('/api/verify/status/:orderId', async (request: FastifyRequest<{ Params: StatusParams }>, reply: FastifyReply) => {
    const { orderId } = request.params;

    if (!UUID_REGEX.test(orderId)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    const result = await query<{
      target_url: string;
      verification_token: string;
      verification_method: string | null;
      verified_at: Date | null;
    }>(
      'SELECT target_url, verification_token, verification_method, verified_at FROM orders WHERE id = $1',
      [orderId],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order nicht gefunden' });
    }

    const order = result.rows[0];

    return reply.send({
      success: true,
      data: {
        verified: !!order.verified_at,
        method: order.verification_method,
        token: order.verification_token,
        domain: order.target_url,
      },
    });
  });
}
