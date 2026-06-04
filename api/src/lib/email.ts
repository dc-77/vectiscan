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

function getSalesLeadEmail(): string {
  // Routing-Ziel fuer eingehende Demo-/Lead-Anfragen. Konfigurierbar via ENV,
  // damit der Vertriebs-Posteingang ohne Code-Aenderung umgezogen werden kann.
  // Default = das einzige nachweislich veroeffentlichte + betreute Postfach
  // (kundenseitige Marken-Domain .gmbh; vectigal.tech ist nur Versand/Infra).
  return process.env.SALES_LEAD_EMAIL || 'kontakt@vectigal.gmbh';
}

export interface DemoLead {
  id: string;
  name?: string | null;
  email: string;
  company?: string | null;
  phone?: string | null;
  targetDomain?: string | null;
  packageInterest?: string | null;
  message?: string | null;
  utmSource?: string | null;
  utmMedium?: string | null;
  utmCampaign?: string | null;
  referrer?: string | null;
}

function esc(value: string | null | undefined): string {
  if (!value) return '—';
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Route an incoming demo/lead request to the sales inbox.
 *
 * Returns `true` only when the mail was accepted by Resend. The caller persists
 * the lead in the DB FIRST and uses this boolean to set `routing_status`, so a
 * disabled or failing mail path never loses a lead ("Leads landen verlaesslich
 * beim Vertrieb").
 */
export async function sendDemoLeadEmail(lead: DemoLead): Promise<boolean> {
  const client = getClient();
  if (!client) {
    // Kein RESEND_API_KEY -> E-Mail-Routing deaktiviert. Der Lead liegt bereits
    // in der DB; der Vertrieb kann ihn ueber GET /api/leads abrufen.
    log.warn({ leadId: lead.id }, 'Demo-lead email skipped — RESEND_API_KEY not set');
    return false;
  }

  const to = getSalesLeadEmail();
  const rows: Array<[string, string | null | undefined]> = [
    ['Name', lead.name],
    ['E-Mail', lead.email],
    ['Unternehmen', lead.company],
    ['Telefon', lead.phone],
    ['Ziel-Domain', lead.targetDomain],
    ['Paket-Interesse', lead.packageInterest],
    ['Quelle (UTM)', [lead.utmSource, lead.utmMedium, lead.utmCampaign].filter(Boolean).join(' / ') || null],
    ['Referrer', lead.referrer],
  ];
  const tableRows = rows
    .map(
      ([k, v]) =>
        `<tr><td style="padding:6px 12px;color:#64748b;font-size:14px;white-space:nowrap;">${k}</td>` +
        `<td style="padding:6px 12px;color:#0f172a;font-size:14px;font-weight:500;">${esc(v)}</td></tr>`,
    )
    .join('');

  try {
    const { error } = await client.emails.send(
      {
        from: getFrom(),
        to,
        replyTo: lead.email,
        subject: `Neue Demo-Anfrage: ${lead.company || lead.email}`,
        html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <h2 style="color: #0f172a;">Neue Demo-/Lead-Anfrage</h2>
          <p style="color: #334155; font-size: 15px;">
            Über das Demo-Formular auf der Website ist eine neue Anfrage eingegangen.
          </p>
          <table style="border-collapse: collapse; margin: 16px 0; width: 100%;">${tableRows}</table>
          ${
            lead.message
              ? `<div style="margin:16px 0;"><p style="color:#64748b;font-size:14px;margin-bottom:4px;">Nachricht</p>` +
                `<div style="background:#f1f5f9;border-radius:6px;padding:12px;color:#0f172a;font-size:14px;white-space:pre-wrap;">${esc(
                  lead.message,
                )}</div></div>`
              : ''
          }
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 24px 0;" />
          <p style="color: #94a3b8; font-size: 12px;">
            Lead-ID: ${esc(lead.id)} &mdash; antworten Sie direkt auf diese E-Mail, um den Interessenten zu kontaktieren.
          </p>
        </div>
      `,
      },
      {
        headers: { 'Idempotency-Key': `demo-lead-${lead.id}` },
      },
    );

    if (error) {
      log.error({ error, leadId: lead.id, to }, 'Failed to route demo-lead email');
      return false;
    }
    log.info({ leadId: lead.id, to }, 'Demo-lead routed to sales');
    return true;
  } catch (err) {
    log.error({ err, leadId: lead.id, to }, 'Error routing demo-lead email');
    return false;
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
