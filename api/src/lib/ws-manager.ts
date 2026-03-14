/**
 * WebSocket Manager — Redis Pub/Sub -> WebSocket broadcast.
 *
 * Subscribes to `scan:events:{orderId}` channels and forwards
 * messages to connected WebSocket clients.
 */
import { createClient, type RedisClientType } from 'redis';
import { type WebSocket } from 'ws';
import { type FastifyBaseLogger } from 'fastify';

/** Map of orderId -> Set of connected WebSocket clients */
const clients = new Map<string, Set<WebSocket>>();

let subscriber: RedisClientType | null = null;
let logger: FastifyBaseLogger | null = null;

export async function initWsManager(log: FastifyBaseLogger): Promise<void> {
  logger = log;
  const url = process.env.REDIS_URL || 'redis://localhost:6379';
  subscriber = createClient({ url }) as RedisClientType;

  subscriber.on('error', (err) => {
    log.error({ err }, 'Redis subscriber error');
  });

  await subscriber.connect();
  log.info('WebSocket manager: Redis subscriber connected');
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
