/**
 * Resend Bounce-/Complaint-/Suppression-Webhook (VEC-188).
 *
 * Restposten F2 aus VEC-173 / VEC-169 (Mail-Amplification / Reputationsschutz):
 * Resend stellt `email.bounced` / `email.complained` via Svix-signiertem Webhook
 * zu. Die betroffene Adresse landet in `email_suppressions`; jeder ausgehende
 * Versand (`lib/email.ts`) prüft die Liste VOR dem Senden und überspringt sie.
 *
 * SICHERHEIT (öffentlicher Endpoint):
 *   - Signaturprüfung ZWINGEND (fail-closed): ohne `RESEND_WEBHOOK_SECRET` → 503,
 *     ungültige/fehlende Svix-Signatur → 400. Sonst könnte ein Angreifer beliebige
 *     Adressen suppressen (DoS gegen Zustellung).
 *   - Idempotent: die Svix-Message-ID (`svix-id`) wird genau einmal beansprucht
 *     (`resend_webhook_events`), denn Resend/Svix retried Zustellungen.
 *
 * Wie der Stripe-Webhook nutzt dieser Scope einen eigenen Buffer-Body-Parser,
 * weil die Svix-Signatur über den rohen, unveränderten Request-Body läuft.
 */
import type { FastifyInstance } from 'fastify';
import { query } from '../lib/db.js';
import { audit } from '../lib/audit.js';
import {
  isResendWebhookConfigured,
  verifyResendWebhook,
  type ResendWebhookEvent,
} from '../lib/resend.js';

/** Empfänger aus `data.to` (String oder Array) → normalisierte, eindeutige Adressen. */
export function extractRecipients(data: ResendWebhookEvent['data']): string[] {
  const raw = data?.to;
  const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const normalized = list
    .filter((v): v is string => typeof v === 'string')
    .map((v) => v.trim().toLowerCase())
    .filter((v) => v.length > 0 && v.includes('@'));
  return Array.from(new Set(normalized));
}

export async function resendWebhookRoutes(server: FastifyInstance): Promise<void> {
  // Svix-Signaturpruefung benoetigt den rohen Body. Wie beim Stripe-Webhook:
  // erst den vom Parent geerbten JSON-Parser droppen, dann den Buffer-Parser
  // im encapsulated Plugin-Scope setzen (sonst FST_ERR_CTP_ALREADY_PRESENT).
  server.removeContentTypeParser('application/json');
  server.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer' },
    (_req, body, done) => {
      done(null, body);
    },
  );

  server.post('/api/webcheck/resend-webhook', async (request, reply) => {
    if (!isResendWebhookConfigured()) {
      return reply.status(503).send({ success: false, error: 'webhook_not_configured' });
    }

    const svixId = request.headers['svix-id'];
    const svixTimestamp = request.headers['svix-timestamp'];
    const svixSignature = request.headers['svix-signature'];
    if (
      typeof svixId !== 'string' ||
      typeof svixTimestamp !== 'string' ||
      typeof svixSignature !== 'string'
    ) {
      return reply.status(400).send({ success: false, error: 'missing_signature' });
    }

    let event: ResendWebhookEvent;
    try {
      event = verifyResendWebhook(request.body as Buffer, {
        'svix-id': svixId,
        'svix-timestamp': svixTimestamp,
        'svix-signature': svixSignature,
      });
    } catch (err) {
      request.log.warn({ err }, 'Resend webhook signature verification failed');
      return reply.status(400).send({ success: false, error: 'invalid_signature' });
    }

    // Idempotenz: svix-id genau einmal beanspruchen. Bei Replay (Resend-Retry)
    // ohne Seiteneffekt 200 quittieren.
    const claim = await query(
      `INSERT INTO resend_webhook_events (id, type) VALUES ($1, $2)
       ON CONFLICT (id) DO NOTHING
       RETURNING id`,
      [svixId, event.type],
    );
    if (claim.rowCount === 0) {
      request.log.info({ svixId }, 'Duplicate Resend event ignored (idempotent)');
      return reply.status(200).send({ received: true, duplicate: true });
    }

    try {
      if (event.type === 'email.bounced' || event.type === 'email.complained') {
        const reason = event.type === 'email.bounced' ? 'bounce' : 'complaint';
        const recipients = extractRecipients(event.data);
        const detail = JSON.stringify({
          type: event.type,
          emailId: event.data?.email_id ?? null,
          bounce: event.data?.bounce ?? null,
        });
        for (const addr of recipients) {
          await query(
            `INSERT INTO email_suppressions (email, reason, detail, source_event_id)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (email) DO UPDATE
               SET reason = EXCLUDED.reason,
                   detail = EXCLUDED.detail,
                   source_event_id = EXCLUDED.source_event_id,
                   updated_at = NOW()`,
            [addr, reason, detail, svixId],
          );
          await audit({
            orderId: null,
            action: 'webcheck.email_suppressed',
            details: { email: addr, reason, emailId: event.data?.email_id ?? null },
            ip: request.ip,
          });
        }
        if (recipients.length === 0) {
          request.log.warn({ svixId, type: event.type }, 'Resend event without resolvable recipient');
        }
      } else {
        request.log.info({ type: event.type }, 'Unhandled Resend event type');
      }
      await query('UPDATE resend_webhook_events SET processed_at = NOW() WHERE id = $1', [svixId]);
    } catch (err) {
      request.log.error({ err, svixId }, 'Error processing Resend event');
      // Idempotenz-Claim zuruecknehmen, damit Resends Retry erneut zustellen kann.
      await query(
        'DELETE FROM resend_webhook_events WHERE id = $1 AND processed_at IS NULL',
        [svixId],
      );
      return reply.status(500).send({ success: false, error: 'processing_error' });
    }

    return reply.status(200).send({ received: true });
  });
}
