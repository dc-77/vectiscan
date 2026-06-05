/**
 * CAPTCHA-Verifikation (Cloudflare Turnstile) für öffentliche, anonyme Endpunkte.
 *
 * VEC-173 (F2 aus VEC-169): Proof-of-Humanity VOR dem DOI-Mail-Versand, um den
 * öffentlichen `POST /api/webcheck/start` gegen Mail-Amplification / Spam-Relay
 * zu härten (OWASP API4 — Unrestricted Resource Consumption).
 *
 * Env-gated: ohne `WEBCHECK_TURNSTILE_SECRET` ist die Prüfung DEAKTIVIERT
 * (`disabled: true`), damit Dev/Test/Server ohne Konfiguration nicht brechen.
 * In Produktion MUSS das Secret gesetzt sein (Launch-Checkliste). Reversibel:
 * Secret entfernen = Prüfung wieder aus (Two-way Door).
 *
 * Fail-Modell: fail-CLOSED, sobald ein Secret konfiguriert ist (Netz-/Parse-/
 * Timeout-Fehler => `ok: false`). Fail-OPEN nur, wenn gar kein Secret gesetzt
 * ist (`disabled: true`) — dann wird nicht geprüft.
 *
 * Provider bewusst gegen hCaptcha austauschbar (gleiche siteverify-Semantik):
 * nur Endpoint + Feldname unterscheiden sich.
 */
import pino from 'pino';

const log = pino({ name: 'captcha' });

const TURNSTILE_VERIFY_URL =
  'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export interface CaptchaResult {
  /** true = Anfrage darf fortfahren (verifiziert ODER Prüfung deaktiviert). */
  ok: boolean;
  /** true = keine CAPTCHA-Konfiguration vorhanden, Prüfung übersprungen. */
  disabled: boolean;
}

/** Ist CAPTCHA aktiv konfiguriert? (Launch-Checkliste prüft das in Prod.) */
export function captchaConfigured(): boolean {
  return Boolean(process.env.WEBCHECK_TURNSTILE_SECRET);
}

/**
 * Verifiziert ein Turnstile-Token gegen Cloudflare.
 * @param token  Vom Client geliefertes Turnstile-Response-Token.
 * @param remoteIp  Optionale Client-IP (Turnstile-Cross-Check).
 */
export async function verifyCaptcha(
  token: unknown,
  remoteIp?: string,
): Promise<CaptchaResult> {
  const secret = process.env.WEBCHECK_TURNSTILE_SECRET;
  if (!secret) {
    log.warn('WEBCHECK_TURNSTILE_SECRET not set — CAPTCHA verification disabled');
    return { ok: true, disabled: true };
  }
  if (typeof token !== 'string' || token.length === 0 || token.length > 4096) {
    return { ok: false, disabled: false };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const form = new URLSearchParams();
    form.set('secret', secret);
    form.set('response', token);
    if (remoteIp) form.set('remoteip', remoteIp);

    const response = await fetch(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form,
      signal: controller.signal,
    });
    const data = (await response.json()) as { success?: boolean };
    return { ok: data.success === true, disabled: false };
  } catch (err) {
    log.error({ err }, 'CAPTCHA verification request failed');
    return { ok: false, disabled: false };
  } finally {
    clearTimeout(timeout);
  }
}
