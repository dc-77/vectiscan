import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import websocket from '@fastify/websocket';
import { initDb } from './lib/db.js';
import { initBuckets } from './lib/minio.js';
import { initWsManager } from './lib/ws-manager.js';
import { authRoutes } from './routes/auth.js';
import { healthRoutes } from './routes/health.js';
import { orderRoutes } from './routes/orders.js';
import { verifyRoutes } from './routes/verify.js';
import { webcheckRoutes } from './routes/webcheck.js';
import { wsRoutes } from './routes/ws.js';
import { scheduleRoutes } from './routes/schedules.js';
import { subscriptionRoutes } from './routes/subscriptions.js';
import { adminReviewRoutes } from './routes/admin-review.js';
import { webhookRoutes } from './routes/webhooks.js';
import { resendWebhookRoutes } from './routes/resend-webhook.js';
import { leadRoutes } from './routes/leads.js';
import { analyticsRoutes } from './routes/analytics.js';
import { liveCheckRoutes } from './routes/live-check.js';
import { startScheduler } from './lib/scheduler.js';
import { registerSecurityHeaders } from './lib/security-headers.js';

export function buildServer() {
  const server = Fastify({
    logger: {
      transport:
        process.env.NODE_ENV === 'development'
          ? { target: 'pino-pretty' }
          : undefined,
    },
  });

  // VEC-166: kanonischer Content-Security-Policy-Header (App-Schicht, testbar).
  registerSecurityHeaders(server);

  server.register(cors, { origin: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'] });

  // VEC-110 — Abuse-/Verfügbarkeits-Hardening (OWASP API4:2023).
  // Rate-Limiting wird NICHT global angewendet (global: false), sondern gezielt
  // per `config.rateLimit` auf den öffentlichen, unauthentifizierten Endpunkten
  // (/api/leads, /api/analytics/collect) opt-in gesetzt. In-Memory-Store: ein
  // Treffer wird hart mit 429 abgewiesen (failure-closed), ohne externe
  // Abhängigkeit (Redis). Einzelne API-Replik laut docker-compose.
  server.register(rateLimit, {
    global: false,
    // Antwortform konsistent zum Projekt-Standard ({ success, error }).
    // `statusCode` muss enthalten sein: das Plugin wirft das Builder-Objekt,
    // Fastify liest daraus den HTTP-Code (sonst 500 statt 429).
    errorResponseBuilder: (_request, context) => ({
      statusCode: context.statusCode,
      success: false,
      error: 'rate_limited',
      retryAfter: Math.ceil(Number(context.ttl) / 1000),
    }),
  });

  // Allow DELETE requests with empty body (browsers may send Content-Length: 0)
  server.addContentTypeParser('application/json', { parseAs: 'string' }, (req, body, done) => {
    if (typeof body === 'string' && body.length === 0) {
      done(null, undefined);
    } else {
      try {
        done(null, JSON.parse(body as string));
      } catch (err) {
        done(err as Error, undefined);
      }
    }
  });
  server.register(websocket);
  server.register(authRoutes);
  server.register(healthRoutes);
  server.register(orderRoutes);
  server.register(verifyRoutes);
  server.register(webcheckRoutes);
  server.register(wsRoutes);
  server.register(scheduleRoutes);
  server.register(subscriptionRoutes);
  server.register(adminReviewRoutes);
  // Encapsulated plugin: nutzt eigenen Buffer-Body-Parser fuer Stripe-Signatur.
  server.register(webhookRoutes);
  // Encapsulated plugin: eigener Buffer-Body-Parser fuer die Resend/Svix-Signatur (VEC-188).
  server.register(resendWebhookRoutes);
  server.register(leadRoutes);
  server.register(analyticsRoutes);
  // VEC-363: Live-Check (SofortScan) Auth-Fassade vor webcheck-core.
  server.register(liveCheckRoutes);

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

    startScheduler();
    server.log.info('Scan scheduler started');
  } catch (err) {
    server.log.error(err);
    process.exit(1);
  }
}

if (require.main === module) {
  start();
}
