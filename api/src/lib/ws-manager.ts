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
import { audit } from './audit.js';
import { computeTimeToValue } from './timeToValue.js';

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

/**
 * Send the scan-complete notification(s) for an order and record the
 * `report.notified` audit event. Exported for unit testing of the PA-4
 * idempotency guard (VEC-32 AC#3). Safe to call repeatedly: recipients that
 * already have a `report.notified` audit entry are skipped.
 */
export async function handleReportComplete(orderId: string): Promise<void> {
  try {
    // Load customer email, subscription report_emails, and download token
    const result = await query(
      // VEC-486: LATERAL + ORDER BY statt eines blanken LEFT JOIN. Solange
      // mehrere reports-Zeilen einer Order `superseded_by IS NULL` tragen
      // (Alt-Datenbestand vor Migration 043), lieferte der Join mehrere Treffer
      // und `rows[0]` war nicht festgelegt — welcher download_token in die
      // Kunden-Mail ging, hing an der Planwahl von Postgres.
      `SELECT c.email, o.target_url AS domain, o.subscription_id,
              r.download_token, s.report_emails
       FROM orders o
       JOIN customers c ON o.customer_id = c.id
       LEFT JOIN LATERAL (
         SELECT download_token
         FROM reports
         WHERE order_id = o.id AND superseded_by IS NULL
         ORDER BY created_at DESC, version DESC, id DESC
         LIMIT 1
       ) r ON true
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

    // Idempotency (PA-4 AC#3): a report regenerate re-sets the order to
    // `report_complete` (report-worker worker.py), which re-fires this handler.
    // Resend's Idempotency-Key only dedupes for ~24h, so a regenerate days
    // later would double-send. Guard at the DB level: skip any recipient that
    // already has a `report.notified` audit entry for this order. This also
    // makes a crashed/retried run (process_lost_retry) safe to resume — only
    // recipients not yet notified get an email.
    const notified = await query(
      `SELECT lower(details->>'recipient') AS recipient
       FROM audit_log
       WHERE order_id = $1 AND action = 'report.notified'`,
      [orderId],
    );
    const alreadyNotified = new Set(
      (notified.rows as Array<{ recipient: string | null }>)
        .map((r) => r.recipient)
        .filter((r): r is string => Boolean(r)),
    );

    // VEC-228: Empfaenger, deren Send NICHT von Resend bestaetigt wurde
    // (sent=false ODER Exception). Bleibt am Schleifenende ein solcher uebrig,
    // wird die Order NICHT auf `delivered` versiegelt und ein observables
    // `report.notify_failed`-Audit geschrieben (Fail Securely + Observability).
    const unconfirmed: string[] = [];

    // Send email to each recipient that has not been notified yet
    for (const email of recipients) {
      if (alreadyNotified.has(email)) {
        logger?.info({ orderId, email }, 'Report notification already sent — skipping (idempotent)');
        continue;
      }
      try {
        const sent = await sendScanCompleteEmail(email, domain, orderId, downloadToken);
        // Fail-Securely (VEC-227): den `report.notified`-Audit NUR bei von
        // Resend bestaetigter Annahme schreiben. Bei transientem Fehler
        // (429/5xx/Netzwerk -> sent=false) bleibt kein Audit zurueck, sodass
        // der bestehende Regenerate/Retry-Pfad denselben Empfaenger erneut
        // anmailt (bewusst at-least-once; Resend-Idempotency-Key dedupt echte
        // Doppelsends ~24h). Ohne diesen Guard wuerde ein geschluckter
        // Sendefehler den Empfaenger dauerhaft als notified markieren und die
        // Report-Mail still verlieren.
        if (!sent) {
          logger?.warn({ orderId, email }, 'Scan-complete email not accepted — leaving unnotified for retry');
          unconfirmed.push(email);
          continue;
        }
        // Audit-Log: persist the dispatch event (PA-4 AC#3) so report
        // delivery is verifiable beyond the application log and serves as
        // the idempotency marker for regenerates/retries.
        await audit({
          orderId,
          action: 'report.notified',
          details: { recipient: email, domain },
        });
      } catch (err) {
        logger?.error({ err, orderId, email }, 'Failed to send report email to recipient');
        unconfirmed.push(email);
      }
    }

    // VEC-87 (PA-7) AC3: Onboarding-Time-to-Value-Messpunkt. Beim ERSTEN
    // report_complete eines Kunden die Spanne Registrierung→Ergebnis als
    // auswertbares Audit-Event festhalten. Fire-and-forget, blockiert die
    // Zustellung nicht.
    await recordTimeToValue(orderId);

    // VEC-228: Order NUR dann als `delivered` versiegeln, wenn KEIN Empfaenger
    // unbestaetigt blieb. Bei mindestens einem unbestaetigten Send bleibt die
    // Order in `report_complete` (recoverable: ein Regenerate feuert den Handler
    // erneut und re-mailt nur die noch nicht notified-Empfaenger) und wir
    // schreiben ein `report.notify_failed`-Audit, damit der sonst stille Verlust
    // beobachtbar/alertbar wird. Linsen: Fail Securely, Complete Mediation,
    // Observability.
    if (unconfirmed.length > 0) {
      logger?.warn(
        { orderId, unconfirmed: unconfirmed.length },
        'Report delivery incomplete — not marking delivered, leaving recoverable for regenerate',
      );
      await audit({
        orderId,
        action: 'report.notify_failed',
        details: { recipients: unconfirmed, domain, count: unconfirmed.length },
      });
      return;
    }

    // Mark order as delivered (alle Empfaenger bestaetigt)
    await query(
      "UPDATE orders SET status = 'delivered', updated_at = NOW() WHERE id = $1 AND status = 'report_complete'",
      [orderId],
    );
  } catch (err) {
    logger?.error({ err, orderId }, 'Failed to send report-complete notification');
  }
}

/**
 * VEC-87 (PA-7) AC3 — schreibt das `onboarding.first_report_complete`-Audit-
 * Event, sobald ein Kunde seinen ersten Report fertig hat. Idempotent über die
 * `priorCompletedCount`-Prüfung: nur der erste abgeschlossene Auftrag erzeugt
 * das Event. Wirft nie (Onboarding-Metrik darf die Zustellung nie blockieren).
 */
async function recordTimeToValue(orderId: string): Promise<void> {
  try {
    const res = await query<{
      registered_at: Date;
      prior_completed: string | number;
    }>(
      `SELECT c.created_at AS registered_at,
              (SELECT COUNT(*) FROM orders o2
                 WHERE o2.customer_id = o.customer_id
                   AND o2.id <> o.id
                   AND o2.status IN ('report_complete', 'delivered')) AS prior_completed
         FROM orders o
         JOIN customers c ON c.id = o.customer_id
        WHERE o.id = $1`,
      [orderId],
    );

    if (res.rows.length === 0) {
      logger?.warn({ orderId }, 'TTV: order not found — skipping onboarding measurement');
      return;
    }

    const row = res.rows[0];
    const ttv = computeTimeToValue({
      registeredAt: new Date(row.registered_at),
      completedAt: new Date(),
      priorCompletedCount: Number(row.prior_completed),
    });

    // null ⇒ nicht der erste Report; Kennzahl bereits erfasst.
    if (!ttv) return;

    await audit({
      orderId,
      action: 'onboarding.first_report_complete',
      details: {
        registeredAt: ttv.registeredAt,
        completedAt: ttv.completedAt,
        ttvSeconds: ttv.ttvSeconds,
        ttvMinutes: Math.round((ttv.ttvSeconds / 60) * 10) / 10,
      },
    });
    logger?.info({ orderId, ttvSeconds: ttv.ttvSeconds }, 'Onboarding time-to-value recorded');
  } catch (err) {
    logger?.error({ err, orderId }, 'Failed to record onboarding time-to-value');
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
