import { Resend } from 'resend';
import pino from 'pino';

const log = pino({ name: 'email' });

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
      idempotencyKey: `scan-complete-${orderId}`,
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
 * Send password reset email with a one-time link.
 */
export async function sendPasswordResetEmail(
  to: string,
  resetToken: string,
): Promise<void> {
  const client = getClient();
  if (!client) return;

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
