/**
 * Stripe webhook handler (PA-1 / VEC-33).
 *
 * Verifiziert die Stripe-Signatur, verarbeitet jedes Event genau einmal
 * (Idempotenz-Ledger stripe_webhook_events) und setzt den Subscription-Status:
 *   checkout.session.completed (paid)  -> 'active'  + Scan-Kontingent frei
 *   checkout.session.expired / failed  -> 'payment_failed' (kein Kontingent)
 *
 * Wichtig: dieser Plugin-Scope nutzt einen eigenen Buffer-Body-Parser, weil
 * die Stripe-Signaturpruefung den rohen, unveraenderten Request-Body braucht.
 */
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type Stripe from 'stripe';
import { query } from '../lib/db.js';
import { enqueuePrecheck } from '../lib/queue.js';
import { audit } from '../lib/audit.js';
import { getStripe, getWebhookSecret, isStripeConfigured } from '../lib/stripe.js';

export async function webhookRoutes(server: FastifyInstance): Promise<void> {
  // Stripe-Signaturpruefung benoetigt den rohen Body. Dieser Parser ist auf
  // den (encapsulated) Webhook-Scope beschraenkt.
  //
  // WICHTIG: server.ts registriert global einen *eigenen* application/json-
  // Parser. Ein vom Parent geerbter custom-Parser ist NICHT ueberschreibbar —
  // ein blosses addContentTypeParser('application/json') wirft hier
  // FST_ERR_CTP_ALREADY_PRESENT und die GESAMTE API bootet nicht
  // (start() faengt es und macht process.exit(1)). Deshalb erst im
  // Plugin-Scope den geerbten Parser droppen, dann den Buffer-Parser setzen.
  // Das bleibt auf diesen encapsulated Scope beschraenkt; alle anderen Routen
  // erhalten weiterhin den geparsten JSON-Body aus server.ts.
  server.removeContentTypeParser('application/json');
  server.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer' },
    (_req, body, done) => {
      done(null, body);
    },
  );

  server.post('/api/webhooks/stripe', async (request, reply) => {
    if (!isStripeConfigured()) {
      return reply.status(503).send({ success: false, error: 'payment_not_configured' });
    }

    const sig = request.headers['stripe-signature'];
    if (!sig || typeof sig !== 'string') {
      return reply.status(400).send({ success: false, error: 'missing_signature' });
    }

    let event: Stripe.Event;
    try {
      event = getStripe().webhooks.constructEvent(
        request.body as Buffer,
        sig,
        getWebhookSecret(),
      );
    } catch (err) {
      request.log.warn({ err }, 'Stripe webhook signature verification failed');
      return reply.status(400).send({ success: false, error: 'invalid_signature' });
    }

    // Idempotenz: Event-ID genau einmal beanspruchen. Bei Konflikt (doppelte
    // Zustellung / Stripe-CLI-Replay) wird ohne Seiteneffekt 200 quittiert.
    const claim = await query(
      `INSERT INTO stripe_webhook_events (id, type) VALUES ($1, $2)
       ON CONFLICT (id) DO NOTHING
       RETURNING id`,
      [event.id, event.type],
    );
    if (claim.rowCount === 0) {
      request.log.info({ eventId: event.id }, 'Duplicate Stripe event ignored (idempotent)');
      return reply.status(200).send({ received: true, duplicate: true });
    }

    try {
      switch (event.type) {
        // Sofortzahlung (Karte) ODER verzoegerte Zahlart, die spaeter erfolgreich
        // einzieht (SEPA-Lastschrift/Sofort — im DE-Mittelstand verbreitet).
        // Bei verzoegerten Methoden feuert 'completed' zuerst mit
        // payment_status 'unpaid' (Abo bleibt korrekt pending), und erst
        // 'async_payment_succeeded' bestaetigt den Geldeingang. Beide muessen
        // auf dieselbe Aktivierungslogik laufen, sonst bleibt ein bezahltes
        // Abo ewig pending (kein Scan-Kontingent).
        case 'checkout.session.completed':
        case 'checkout.session.async_payment_succeeded':
          await handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session, request);
          break;
        case 'checkout.session.expired':
        case 'checkout.session.async_payment_failed':
          await handlePaymentFailed(event.data.object as Stripe.Checkout.Session, request);
          break;
        default:
          request.log.info({ type: event.type }, 'Unhandled Stripe event type');
      }
      await query('UPDATE stripe_webhook_events SET processed_at = NOW() WHERE id = $1', [event.id]);
    } catch (err) {
      request.log.error({ err, eventId: event.id }, 'Error processing Stripe event');
      // Idempotenz-Claim zuruecknehmen, damit Stripes Retry erneut zustellen kann.
      await query(
        'DELETE FROM stripe_webhook_events WHERE id = $1 AND processed_at IS NULL',
        [event.id],
      );
      return reply.status(500).send({ success: false, error: 'processing_error' });
    }

    return reply.status(200).send({ received: true });
  });
}

/**
 * Aktiviert das Abo NUR nach bestaetigter Zahlung. Der WHERE-Filter auf
 * status IN ('pending','payment_failed') ist die zweite Idempotenz-Schicht:
 * ein bereits aktives Abo wird nicht erneut aktiviert (0 rows).
 */
async function handleCheckoutCompleted(
  session: Stripe.Checkout.Session,
  request: FastifyRequest,
): Promise<void> {
  const subscriptionId = session.metadata?.subscription_id;
  if (!subscriptionId) {
    request.log.warn({ sessionId: session.id }, 'checkout.session.completed ohne subscription_id-Metadata');
    return;
  }

  // Nur aktivieren, wenn die Zahlung tatsaechlich erfolgt ist.
  if (
    session.payment_status &&
    session.payment_status !== 'paid' &&
    session.payment_status !== 'no_payment_required'
  ) {
    request.log.info(
      { subscriptionId, paymentStatus: session.payment_status },
      'Checkout completed aber noch nicht bezahlt — Abo bleibt pending',
    );
    return;
  }

  const amountCents = session.amount_total ?? 0;
  const stripeSubId =
    typeof session.subscription === 'string'
      ? session.subscription
      : session.subscription?.id ?? null;
  const priceId = session.metadata?.price_id ?? null;
  const currency = session.currency ? session.currency.toUpperCase() : null;

  const upd = await query<{ id: string }>(
    `UPDATE subscriptions
        SET status = 'active',
            paid_at = NOW(),
            amount_cents = $2,
            currency = COALESCE($3, currency),
            stripe_subscription_id = COALESCE($4, stripe_subscription_id),
            stripe_price_id = COALESCE($5, stripe_price_id),
            stripe_checkout_session_id = $6,
            started_at = COALESCE(started_at, NOW()),
            updated_at = NOW()
      WHERE id = $1 AND status IN ('pending', 'payment_failed')
      RETURNING id`,
    [subscriptionId, amountCents, currency, stripeSubId, priceId, session.id],
  );

  if (upd.rowCount === 0) {
    request.log.info({ subscriptionId }, 'Abo nicht in aktivierbarem Status — uebersprungen');
    return;
  }

  // Erst jetzt Scan-Kontingent freischalten: Pre-Check fuer die Targets queuen.
  const targets = await query<{ id: string }>(
    `SELECT id FROM scan_targets WHERE subscription_id = $1 AND status = 'pending_precheck'`,
    [subscriptionId],
  );
  const targetIds = targets.rows.map((r) => r.id);
  if (targetIds.length > 0) {
    await enqueuePrecheck({ subscriptionId, targetIds });
  }

  await audit({
    action: 'subscription.payment_confirmed',
    details: { subscriptionId, amountCents, stripeSubId, sessionId: session.id, targetCount: targetIds.length },
  });
}

/** Markiert das Abo als payment_failed — kein Scan-Kontingent wird frei. */
async function handlePaymentFailed(
  session: Stripe.Checkout.Session,
  request: FastifyRequest,
): Promise<void> {
  const subscriptionId = session.metadata?.subscription_id;
  if (!subscriptionId) {
    request.log.warn({ sessionId: session.id }, 'Payment-Failed-Event ohne subscription_id-Metadata');
    return;
  }
  await query(
    `UPDATE subscriptions SET status = 'payment_failed', updated_at = NOW()
      WHERE id = $1 AND status = 'pending'`,
    [subscriptionId],
  );
  await audit({
    action: 'subscription.payment_failed',
    details: { subscriptionId, sessionId: session.id },
  });
}
