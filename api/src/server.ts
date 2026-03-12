import Fastify from 'fastify';

export function buildServer() {
  const server = Fastify({
    logger: {
      transport:
        process.env.NODE_ENV === 'development'
          ? { target: 'pino-pretty' }
          : undefined,
    },
  });

  server.get('/health', async () => {
    return { success: true, data: { status: 'ok' } };
  });

  return server;
}

async function start() {
  const server = buildServer();
  const port = Number(process.env.PORT) || 4000;
  const host = process.env.HOST || '0.0.0.0';

  try {
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
