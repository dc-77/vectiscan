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
import { getPackage } from './catalog.generated.js';

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
 * Ob ein Paket als kostenpflichtiger Self-Service-Einzelkauf (mode=payment)
 * angeboten wird (VEC-436/D1). Wahrheitsquelle ist der Katalog: nur Pakete
 * mit `oneTimePriceEnvKey` sind Einzelkauf-pflichtig (heute nur Perimeter).
 * WebCheck (free) und die sales_assisted-Pakete tragen den Key nicht.
 */
export function isOneTimePurchasable(pkg: string): boolean {
  return Boolean(getPackage(pkg)?.oneTimePriceEnvKey);
}

/**
 * Stripe one-time Price-ID fuer den Einzelscan-Kauf eines Pakets (VEC-436).
 * Liest den im Katalog hinterlegten ENV-Key (z. B. STRIPE_PRICE_PERIMETER_ONETIME),
 * faellt sonst auf die Namenskonvention STRIPE_PRICE_<PKG>_ONETIME zurueck.
 * Bewusst KEIN STRIPE_PRICE_DEFAULT-Fallback — die one-time-ID muss strikt
 * getrennt vom Jahres-Abo sein, sonst wuerde ein Einzelkauf ein Abo abrechnen.
 */
export function getOneTimePriceIdForPackage(pkg: string): string | null {
  const envKey = getPackage(pkg)?.oneTimePriceEnvKey || `STRIPE_PRICE_${pkg.toUpperCase()}_ONETIME`;
  return process.env[envKey] || null;
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

/**
 * Erfolgs-/Abbruch-URLs fuer den Einzelscan-Checkout (mode=payment, VEC-436).
 * Erfolg fuehrt zur Order-Detailseite, wo der Scan-Fortschritt erscheint,
 * sobald der Webhook die Zahlung bestaetigt und den Precheck enqueued hat.
 */
export function getOrderCheckoutUrls(orderId: string): { successUrl: string; cancelUrl: string } {
  const base = process.env.APP_BASE_URL || 'https://scan.vectigal.tech';
  return {
    successUrl:
      process.env.STRIPE_ORDER_SUCCESS_URL ||
      `${base}/scan/${orderId}?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
    cancelUrl: process.env.STRIPE_ORDER_CANCEL_URL || `${base}/scan/new?checkout=cancelled`,
  };
}
