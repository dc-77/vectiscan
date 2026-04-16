/**
 * WebSocket Manager — Redis Pub/Sub -> WebSocket broadcast.
 *
 * Subscribes to `scan:events:{orderId}` channels and forwards
 * messages to connected WebSocket clients.
 *
 * Also triggers scan-complete email notifications via a global
 * pattern subscription on `scan:events:*`.
 */
import { createClient, type RedisClientType } from 'redis';
import { type WebSocket } from 'ws';
import { type FastifyBaseLogger } from 'fastify';
import { query } from './db.js';
import { sendScanCompleteEmail } from './email.js';

/** Map of orderId -> Set of connected WebSocket clients */
const clients = new Map<string, Set<WebSocket>>();

let subscriber: RedisClientType | null = null;
let emailSubscriber: RedisClientType | null = null;
let logger: FastifyBaseLogger | null = null;

export async function initWsManager(log: FastifyBaseLogger): Promise<void> {
  logger = log;
  const url = process.env.REDIS_URL || 'redis://localhost:6379';

  // Primary subscriber for per-order WebSocket forwarding
  subscriber = createClient({ url }) as RedisClientType;
  subscriber.on('error', (err) => {
    log.error({ err }, 'Redis subscriber error');
  });
  await subscriber.connect();
  log.info('WebSocket manager: Redis subscriber connected');

  // Secondary subscriber for global email notifications (pSubscribe)
  emailSubscriber = createClient({ url }) as RedisClientType;
  emailSubscriber.on('error', (err) => {
    log.error({ err }, 'Redis email-subscriber error');
  });
  await emailSubscriber.connect();

  await emailSubscriber.pSubscribe('scan:events:*', async (message, channel) => {
    try {
      const event = JSON.parse(message);
      if (event.type === 'status' && event.status === 'report_complete' && event.orderId) {
        await handleReportComplete(event.orderId);
      }
    } catch (err) {
      log.error({ err, channel }, 'Error processing email notification event');
    }
  });
  log.info('Email notification subscriber: listening on scan:events:*');
}

async function handleReportComplete(orderId: string): Promise<void> {
  try {
    // Load customer email, subscription report_emails, and download token
    const result = await query(
      `SELECT c.email, o.target_url AS domain, o.subscription_id,
              r.download_token, s.report_emails
       FROM orders o
       JOIN customers c ON o.customer_id = c.id
       LEFT JOIN reports r ON r.order_id = o.id AND r.superseded_by IS NULL
       LEFT JOIN subscriptions s ON s.id = o.subscription_id
       WHERE o.id = $1`,
      [orderId],
    );

    if (result.rows.length === 0) {
      logger?.warn({ orderId }, 'report_complete event but order not found');
      return;
    }

    const row = result.rows[0] as Record<string, unknown>;
    const customerEmail = row.email as string;
    const domain = row.domain as string;
    const downloadToken = row.download_token as string | null;
    const reportEmails = (row.report_emails as string[] | null) || [];

    if (!downloadToken) {
      logger?.warn({ orderId, downloadToken }, 'Missing download token — skipping notification');
      return;
    }

    // Collect all unique email recipients: subscription report_emails + customer email
    const recipients = new Set<string>();
    for (const e of reportEmails) {
      if (e) recipients.add(e.toLowerCase());
    }
    if (customerEmail) recipients.add(customerEmail.toLowerCase());

    // Send email to each recipient
    for (const email of recipients) {
      try {
        await sendScanCompleteEmail(email, domain, orderId, downloadToken);
      } catch (err) {
        logger?.error({ err, orderId, email }, 'Failed to send report email to recipient');
      }
    }

    // Mark order as delivered
    await query(
      "UPDATE orders SET status = 'delivered', updated_at = NOW() WHERE id = $1 AND status = 'report_complete'",
      [orderId],
    );
  } catch (err) {
    logger?.error({ err, orderId }, 'Failed to send report-complete notification');
  }
}

export function subscribe(orderId: string, ws: WebSocket): void {
  if (!clients.has(orderId)) {
    clients.set(orderId, new Set());

    // Subscribe to Redis channel for this order (channel name kept for backward compat)
    const channel = `scan:events:${orderId}`;
    subscriber?.subscribe(channel, (message) => {
      const sockets = clients.get(orderId);
      if (!sockets) return;

      for (const socket of sockets) {
        if (socket.readyState === socket.OPEN) {
          socket.send(message);
        }
      }
    }).catch((err) => {
      logger?.error({ err, orderId }, 'Failed to subscribe to Redis channel');
    });
  }

  clients.get(orderId)!.add(ws);
  logger?.debug({ orderId, clients: clients.get(orderId)!.size }, 'WebSocket client subscribed');
}

export function unsubscribe(orderId: string, ws: WebSocket): void {
  const sockets = clients.get(orderId);
  if (!sockets) return;

  sockets.delete(ws);

  if (sockets.size === 0) {
    clients.delete(orderId);
    const channel = `scan:events:${orderId}`;
    subscriber?.unsubscribe(channel).catch((err) => {
      logger?.error({ err, orderId }, 'Failed to unsubscribe from Redis channel');
    });
  }
}

export function getClientCount(): number {
  let total = 0;
  for (const sockets of clients.values()) {
    total += sockets.size;
  }
  return total;
}
