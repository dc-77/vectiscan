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
  return process.env.RESEND_FROM_EMAIL || 'VectiScan <noreply@vectiscan.de>';
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
 *
 * Returns `true` only when the mail was accepted by Resend. The caller
 * (`handleReportComplete`) writes the `report.notified` idempotency audit ONLY
 * on `true`, so a transient send failure (429/5xx/network) leaves no audit and
 * the existing regenerate/retry path re-attempts later (bewusst at-least-once;
 * Resend `Idempotency-Key: scan-complete-${orderId}` dedupes echte Doppelsends
 * innerhalb ~24h). Fail-Securely: ein geschluckter Fehler würde sonst einen
 * Empfänger dauerhaft als „notified" markieren und die Report-Mail still
 * verlieren (VEC-227).
 */
export async function sendScanCompleteEmail(
  to: string,
  domain: string,
  orderId: string,
  downloadToken: string,
): Promise<boolean> {
  const client = getClient();
  if (!client) return false;
  if (await skipIfSuppressed(to)) return false;

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
      return false;
    }
    log.info({ to, orderId, domain }, 'Scan-complete email sent');
    return true;
  } catch (err) {
    log.error({ err, to, orderId }, 'Error sending scan-complete email');
    return false;
  }
}

function getSalesLeadEmail(): string | string[] {
  // Routing-Ziel fuer eingehende Demo-/Lead-Anfragen. Konfigurierbar via ENV,
  // damit der Vertriebs-Posteingang ohne Code-Aenderung umgezogen werden kann.
  // Mehrere Empfaenger sind komma-separiert erlaubt (Redundanz: der Lead landet
  // in JEDEM genannten Postfach).
  // WICHTIG (VEC-36): Das fruehere Default 'kontakt@vectigal.gmbh' war ein
  // UNbetreutes Postfach. Resend nahm den Send an (routed:true), aber die Mail
  // erreichte den Vertrieb nie -> Akzeptanz "Leads landen verlaesslich beim
  // Vertrieb" war faktisch verletzt. Default zeigt jetzt auf die vom Vertrieb
  // bestaetigten, real abgerufenen Marken-Postfaecher (support@vectiscan.de
  // leitet an kontakt@vectigal.ai weiter). Empfaenger MUSS ein abgerufenes
  // Postfach sein, sonst ist 'routed:true' wertlos.
  const raw = process.env.SALES_LEAD_EMAIL || 'support@vectiscan.de,kontakt@vectigal.ai';
  const list = raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return list.length > 1 ? list : list[0] || 'support@vectiscan.de';
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
