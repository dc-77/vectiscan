import { FastifyInstance } from 'fastify';

export async function healthRoutes(server: FastifyInstance): Promise<void> {
  server.get('/health', async () => {
    return { status: 'ok', timestamp: new Date().toISOString() };
  });
}
