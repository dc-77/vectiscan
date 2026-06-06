/**
 * Resend-Webhook-Verifikation (VEC-188).
 *
 * Resend signiert Webhook-Zustellungen via Svix (Header `svix-id`/
 * `svix-timestamp`/`svix-signature`). Die Verifikation ist ZWINGEND fail-closed:
 * ohne gesetztes `RESEND_WEBHOOK_SECRET` verarbeitet die Route gar nichts (503),
 * eine ungültige Signatur wird mit 400 abgewiesen. Ohne diese Prüfung wäre der
 * öffentliche Endpoint ein Spoofing-Vektor (beliebige Adresse suppressbar).
 *
 * Das Secret (`whsec_…`) gehört als env/CI-Var konfiguriert, NICHT in den Code.
 * Dünne Wrapper-Schicht analog zu `lib/stripe.ts`, damit der Webhook-Handler die
 * Signaturprüfung im Test sauber mocken kann.
 */
import { Webhook } from 'svix';

/** Relevante Felder der Resend-Webhook-Payload (defensiv, Rest ignoriert). */
export interface ResendWebhookEvent {
  type: string;
  created_at?: string;
  data?: {
    email_id?: string;
    from?: string;
    /** Empfänger — Resend liefert i. d. R. ein Array, toleriert wird auch String. */
    to?: string | string[];
    subject?: string;
    bounce?: { type?: string; subType?: string; message?: string };
    [k: string]: unknown;
  };
}

export function getResendWebhookSecret(): string | undefined {
  return process.env.RESEND_WEBHOOK_SECRET;
}

/** Ist die Webhook-Verifikation konfiguriert? (Route ist sonst 503/fail-closed.) */
export function isResendWebhookConfigured(): boolean {
  return Boolean(process.env.RESEND_WEBHOOK_SECRET);
}

/**
 * Verifiziert die Svix-Signatur über den ROHEN Request-Body und gibt die
 * geparste Payload zurück. Wirft bei ungültiger/fehlender Signatur — der
 * Aufrufer übersetzt das in 400 (fail-closed).
 */
export function verifyResendWebhook(
  rawBody: Buffer | string,
  headers: { 'svix-id': string; 'svix-timestamp': string; 'svix-signature': string },
): ResendWebhookEvent {
  const secret = getResendWebhookSecret();
  if (!secret) {
    // Defensiv: die Route prüft isResendWebhookConfigured() vorher.
    throw new Error('RESEND_WEBHOOK_SECRET not configured');
  }
  const wh = new Webhook(secret);
  const payload = typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8');
  return wh.verify(payload, headers) as ResendWebhookEvent;
}
