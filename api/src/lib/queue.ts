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

export async function publishEvent(scanId: string, event: Record<string, unknown>): Promise<void> {
  const client = await getRedisClient();
  await client.publish(`scan:events:${scanId}`, JSON.stringify(event));
}
