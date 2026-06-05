import { Resend } from 'resend';
import pino from 'pino';
import { query } from './db.js';
import { audit } from './audit.js';

const log = pino({ name: 'email' });

/**
 * Steht die Empfänger-Adresse auf der Suppression-Liste (VEC-188)?
 *
 * Gespeist aus Resend Bounce-/Complaint-Webhooks (`routes/resend-webhook.ts`).
 * FAIL-OPEN: schlägt der Lookup fehl (DB-Hiccup), wird gesendet — eine
 * unterdrückte legitime Transaktionsmail wäre schlimmer als ein Extra-Versand
 * an eine eventuell tote Adresse. Suppression ist Reputationsschutz, kein
 * Security-Gate.
 */
export async function isEmailSuppressed(email: string): Promise<boolean> {
  try {
    const res = await query<{ email: string }>(
      'SELECT email FROM email_suppressions WHERE email = $1 LIMIT 1',
      [email.trim().toLowerCase()],
    );
    return res.rows.length > 0;
  } catch (err) {
    log.error({ err, email }, 'Suppression lookup failed — failing OPEN (send proceeds)');
    return false;
  }
}

/**
 * Pre-Send-Gate: true = Empfänger ist suppressed → Versand überspringen.
 * Schreibt ein Audit-Event für die Forensik (warum kam keine Mail an?).
 */
async function skipIfSuppressed(to: string): Promise<boolean> {
  if (await isEmailSuppressed(to)) {
    log.info({ to }, 'Recipient on suppression list — email skipped');
    await audit({ orderId: null, action: 'webcheck.suppression_skipped', details: { to } });
    return true;
  }
  return false;
}

let resend: Resend | null = null;

function getClient(): Resend | null {
  if (resend) return resend;
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    log.warn('RESEND_API_KEY not set — emails disabled');
    return null;
  }
  resend = new Resend(apiKey);
  return resend;
}

function getFrom(): string {
  return process.env.RESEND_FROM_EMAIL || 'VectiScan <noreply@vectigal.tech>';
}

function getFrontendUrl(): string {
  return process.env.FRONTEND_URL || 'https://scan.vectigal.tech';
}

function getApiUrl(): string {
  return process.env.API_URL || 'https://scan-api.vectigal.tech';
}

/**
 * Send scan-complete notification with report download link.
 * Uses the download_token from the reports table (no login needed).
 */
export async function sendScanCompleteEmail(
  to: string,
  domain: string,
  orderId: string,
  downloadToken: string,
): Promise<void> {
  const client = getClient();
  if (!client) return;
  if (await skipIfSuppressed(to)) return;

  const downloadUrl = `${getApiUrl()}/api/orders/${orderId}/report?download_token=${downloadToken}`;
  const dashboardUrl = `${getFrontendUrl()}/dashboard`;

  try {
    const { error } = await client.emails.send({
      from: getFrom(),
      to,
      subject: `Security-Scan abgeschlossen: ${domain}`,
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #0f172a;">Ihr Security-Scan ist fertig</h2>
          <p style="color: #334155; font-size: 16px;">
            Der Scan f&uuml;r <strong>${domain}</strong> wurde erfolgreich abgeschlossen.
            Ihr PDF-Report steht zum Download bereit.
          </p>
          <div style="margin: 30px 0;">
            <a href="${downloadUrl}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 16px;">
              PDF-Report herunterladen
            </a>
          </div>
          <p style="color: #64748b; font-size: 14px;">
            Oder besuchen Sie Ihr <a href="${dashboardUrl}" style="color: #2563eb;">Dashboard</a> f&uuml;r eine &Uuml;bersicht aller Scans.
          </p>
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;" />
          <p style="color: #94a3b8; font-size: 12px;">
            VectiScan &mdash; Automatisierte Security-Scan-Plattform
          </p>
        </div>
      `,
    }, {
      headers: { 'Idempotency-Key': `scan-complete-${orderId}` },
    });

    if (error) {
      log.error({ error, to, orderId }, 'Failed to send scan-complete email');
    } else {
      log.info({ to, orderId, domain }, 'Scan-complete email sent');
    }
  } catch (err) {
    log.error({ err, to, orderId }, 'Error sending scan-complete email');
  }
}

/**
 * Send WebCheck-Free double-opt-in confirmation email (VEC-91 / PA-11, DSGVO AC5).
 *
 * Bestätigt die Marketing-Einwilligung getrennt vom transaktionalen Report-Mail.
 * HINWEIS: Die finale Copy + der Rechtsgrundlagen-/Widerrufstext werden von Greta
 * (CMO/DSGVO) geliefert (VEC-91-Child). Bis dahin ein DSGVO-konformer Platzhalter
 * mit Double-Opt-in-Link und Hinweis auf die Trennung von Produktdaten.
 */
export async function sendWebcheckDoiEmail(
  to: string,
  domain: string,
  doiToken: string,
): Promise<void> {
  const client = getClient();
  if (!client) return;
  if (await skipIfSuppressed(to)) return;

  const confirmUrl = `${getApiUrl()}/api/webcheck/doi/confirm?token=${doiToken}`;

  try {
    const { error } = await client.emails.send({
      from: getFrom(),
      to,
      subject: 'Bitte bestätigen Sie Ihren WebCheck-Free-Report',
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #0f172a;">Nur noch ein Klick</h2>
          <p style="color: #334155; font-size: 16px;">
            Sie haben einen kostenlosen WebCheck f&uuml;r <strong>${domain}</strong> angefordert.
            Bitte best&auml;tigen Sie Ihre E-Mail-Adresse, damit wir Ihnen den Report
            zusenden d&uuml;rfen.
          </p>
          <div style="margin: 30px 0;">
            <a href="${confirmUrl}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 16px;">
              E-Mail best&auml;tigen
            </a>
          </div>
          <p style="color: #64748b; font-size: 14px;">
            Falls Sie diese Anfrage nicht gestellt haben, k&ouml;nnen Sie diese E-Mail ignorieren &mdash;
            ohne Best&auml;tigung verarbeiten wir Ihre Daten nicht zu Marketingzwecken.
          </p>
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;" />
          <p style="color: #94a3b8; font-size: 12px;">
            VectiScan &mdash; Automatisierte Security-Scan-Plattform
          </p>
        </div>
      `,
    }, {
      headers: { 'Idempotency-Key': `webcheck-doi-${doiToken}` },
    });

    if (error) {
      log.error({ error, to, domain }, 'Failed to send WebCheck DOI email');
    } else {
      log.info({ to, domain }, 'WebCheck DOI email sent');
    }
  } catch (err) {
    log.error({ err, to, domain }, 'Error sending WebCheck DOI email');
  }
}

/**
 * Send password reset email with a one-time link.
 */
export async function sendPasswordResetEmail(
  to: string,
  resetToken: string,
): Promise<void> {
  const client = getClient();
  if (!client) return;
  if (await skipIfSuppressed(to)) return;

  const resetUrl = `${getFrontendUrl()}/reset-password?token=${resetToken}`;

  try {
    const { error } = await client.emails.send({
      from: getFrom(),
      to,
      subject: 'Passwort zur\u00fccksetzen — VectiScan',
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #0f172a;">Passwort zur&uuml;cksetzen</h2>
          <p style="color: #334155; font-size: 16px;">
            Sie haben eine Passwort-Zur&uuml;cksetzung angefordert.
            Klicken Sie auf den Button, um ein neues Passwort zu vergeben.
          </p>
          <div style="margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 16px;">
              Neues Passwort setzen
            </a>
          </div>
          <p style="color: #64748b; font-size: 14px;">
            Dieser Link ist 1 Stunde g&uuml;ltig. Falls Sie diese Anfrage nicht gestellt haben, k&ouml;nnen Sie diese E-Mail ignorieren.
          </p>
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;" />
          <p style="color: #94a3b8; font-size: 12px;">
            VectiScan &mdash; Automatisierte Security-Scan-Plattform
          </p>
        </div>
      `,
    });

    if (error) {
      log.error({ error, to }, 'Failed to send password-reset email');
    } else {
      log.info({ to }, 'Password-reset email sent');
    }
  } catch (err) {
    log.error({ err, to }, 'Error sending password-reset email');
  }
}
