/**
 * WebSocket Manager — Redis Pub/Sub → WebSocket broadcast.
 *
 * Subscribes to `scan:events:{scanId}` channels and forwards
 * messages to connected WebSocket clients.
 */
import { createClient, type RedisClientType } from 'redis';
import { type WebSocket } from 'ws';
import { type FastifyBaseLogger } from 'fastify';

/** Map of scanId → Set of connected WebSocket clients */
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

export function subscribe(scanId: string, ws: WebSocket): void {
  if (!clients.has(scanId)) {
    clients.set(scanId, new Set());

    // Subscribe to Redis channel for this scan
    const channel = `scan:events:${scanId}`;
    subscriber?.subscribe(channel, (message) => {
      const sockets = clients.get(scanId);
      if (!sockets) return;

      for (const socket of sockets) {
        if (socket.readyState === socket.OPEN) {
          socket.send(message);
        }
      }
    }).catch((err) => {
      logger?.error({ err, scanId }, 'Failed to subscribe to Redis channel');
    });
  }

  clients.get(scanId)!.add(ws);
  logger?.debug({ scanId, clients: clients.get(scanId)!.size }, 'WebSocket client subscribed');
}

export function unsubscribe(scanId: string, ws: WebSocket): void {
  const sockets = clients.get(scanId);
  if (!sockets) return;

  sockets.delete(ws);

  if (sockets.size === 0) {
    clients.delete(scanId);
    const channel = `scan:events:${scanId}`;
    subscriber?.unsubscribe(channel).catch((err) => {
      logger?.error({ err, scanId }, 'Failed to unsubscribe from Redis channel');
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
