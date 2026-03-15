import { createClient } from 'redis';

let redisClient: ReturnType<typeof createClient> | null = null;

async function getRedisClient() {
  if (!redisClient) {
    const url = process.env.REDIS_URL || 'redis://localhost:6379';
    redisClient = createClient({ url });
    await redisClient.connect();
  }
  return redisClient;
}

export const scanQueue = {
  async add(_name: string, data: Record<string, unknown>) {
    const client = await getRedisClient();
    await client.rPush('scan-pending', JSON.stringify(data));
  },
};

export const reportQueue = {
  async add(_name: string, data: Record<string, unknown>) {
    const client = await getRedisClient();
    await client.rPush('report-pending', JSON.stringify(data));
  },
};

export async function publishEvent(orderId: string, event: Record<string, unknown>): Promise<void> {
  const client = await getRedisClient();
  // Channel name kept as scan:events:{id} for backward compat with workers
  await client.publish(`scan:events:${orderId}`, JSON.stringify(event));
}

export async function getProgressFromRedis(orderId: string): Promise<Record<string, unknown> | null> {
  try {
    const client = await getRedisClient();
    const raw = await client.get(`order:progress:${orderId}`);
    if (raw) {
      return JSON.parse(raw) as Record<string, unknown>;
    }
  } catch {
    // Redis unavailable — fall back to DB data
  }
  return null;
}
