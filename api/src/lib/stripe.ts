/**
 * Stripe client + configuration helpers (PA-1 / VEC-33).
 *
 * Alle Credentials kommen ausschliesslich aus ENV (nie hardcoded, siehe
 * CLAUDE.md). Die Implementierung ist credential-agnostisch: ohne gesetzte
 * Keys faellt jeder zahlungsrelevante Endpunkt sauber auf 503 zurueck,
 * statt — wie bisher — kostenlose aktive Abos zu erzeugen.
 *
 * Benoetigte ENV (von der CEO als Deploy-Secrets zu liefern):
 *   STRIPE_SECRET_KEY        sk_live_... (bzw. sk_test_... fuer Staging)
 *   STRIPE_WEBHOOK_SECRET    whsec_...
 *   STRIPE_PRICE_<PACKAGE>   price_...  (z.B. STRIPE_PRICE_PERIMETER)
 *   STRIPE_PRICE_DEFAULT     price_...  (Fallback fuer alle Pakete)
 *   STRIPE_SUCCESS_URL / STRIPE_CANCEL_URL  (optional, sonst APP_BASE_URL)
 *   APP_BASE_URL             https://scan.vectigal.tech
 */
import Stripe from 'stripe';

let _stripe: Stripe | null = null;

/** True, wenn der Stripe-Secret-Key konfiguriert ist. */
export function isStripeConfigured(): boolean {
  return Boolean(process.env.STRIPE_SECRET_KEY);
}

/** Lazy Stripe-Singleton. Wirft, wenn nicht konfiguriert. */
export function getStripe(): Stripe {
  if (!process.env.STRIPE_SECRET_KEY) {
    throw new Error('STRIPE_SECRET_KEY ist nicht konfiguriert.');
  }
  if (!_stripe) {
    _stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  }
  return _stripe;
}

/** Webhook-Signing-Secret. Wirft, wenn nicht konfiguriert. */
export function getWebhookSecret(): string {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) {
    throw new Error('STRIPE_WEBHOOK_SECRET ist nicht konfiguriert.');
  }
  return secret;
}

/**
 * Stripe-Price-ID fuer ein Paket. Bevorzugt paket-spezifisches
 * STRIPE_PRICE_<PACKAGE>, faellt sonst auf STRIPE_PRICE_DEFAULT zurueck.
 * Gibt null zurueck, wenn keine Price-ID hinterlegt ist.
 */
export function getPriceIdForPackage(pkg: string): string | null {
  const specific = process.env[`STRIPE_PRICE_${pkg.toUpperCase()}`];
  return specific || process.env.STRIPE_PRICE_DEFAULT || null;
}

/**
 * Ob `payment_status === 'no_payment_required'` ein Abo aktivieren darf
 * (VEC-112/L2). Heute aktiviert Stripe dies nur bei 100%-Coupons/Trials —
 * und genau die sind im aktuellen Checkout NICHT aktiviert (feste line_items,
 * keine allow_promotion_codes). Ein 'no_payment_required'-Event ist daher
 * unerwartet und wird per Default NICHT als kostenlose Aktivierung akzeptiert.
 * Erst wenn Gutscheine/Trials bewusst eingefuehrt werden, schaltet das
 * Deploy-Secret STRIPE_ALLOW_FREE_ACTIVATION=true die Aktivierung frei.
 */
export function isFreeActivationAllowed(): boolean {
  return process.env.STRIPE_ALLOW_FREE_ACTIVATION === 'true';
}

/** Erfolgs-/Abbruch-URLs fuer die Checkout-Session. */
export function getCheckoutUrls(): { successUrl: string; cancelUrl: string } {
  const base = process.env.APP_BASE_URL || 'https://scan.vectigal.tech';
  return {
    successUrl:
      process.env.STRIPE_SUCCESS_URL ||
      `${base}/subscriptions?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
    cancelUrl: process.env.STRIPE_CANCEL_URL || `${base}/subscriptions?checkout=cancelled`,
  };
}
