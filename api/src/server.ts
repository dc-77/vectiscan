import Fastify from 'fastify';
import cors from '@fastify/cors';
import websocket from '@fastify/websocket';
import { initDb } from './lib/db.js';
import { initBuckets } from './lib/minio.js';
import { initWsManager } from './lib/ws-manager.js';
import { authRoutes } from './routes/auth.js';
import { healthRoutes } from './routes/health.js';
import { scanRoutes } from './routes/scans.js';
import { wsRoutes } from './routes/ws.js';

export function buildServer() {
  const server = Fastify({
    logger: {
      transport:
        process.env.NODE_ENV === 'development'
          ? { target: 'pino-pretty' }
          : undefined,
    },
  });

  server.register(cors, { origin: true });
  server.register(websocket);
  server.register(authRoutes);
  server.register(healthRoutes);
  server.register(scanRoutes);
  server.register(wsRoutes);

  return server;
}

async function start() {
  const server = buildServer();
  const port = Number(process.env.PORT) || 4000;
  const host = process.env.HOST || '0.0.0.0';

  try {
    await initDb();
    server.log.info('Database initialized');

    await initBuckets();
    server.log.info('MinIO buckets verified');

    await initWsManager(server.log);
    server.log.info('WebSocket manager initialized');

    await server.listen({ port, host });
    server.log.info(`VectiScan API started on ${host}:${port}`);
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

if (require.main === module) {
  start();
}
