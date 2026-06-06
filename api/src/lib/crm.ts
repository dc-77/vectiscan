/**
 * CRM-Anbindung (VEC-301): Upsert eingewilligter Leads ins self-hosted Twenty CRM.
 * --------------------------------------------------------------------------
 * Board-Entscheidung (VEC-136): Twenty CRM self-hosted auf eigener EU-Infra,
 * Resend als einziger Mailer. Der DOI-Mailversand läuft unverändert über den
 * bestehenden Resend-Pfad (`email.ts` → `sendWebcheckDoiEmail`); dieses Modul
 * macht NUR den CRM-Upsert + optionale Vertriebs-Benachrichtigung.
 *
 * DSGVO (VEC-89 §4.5 / VEC-173 Kopplungsverbot): Ein Lead wird erst ins CRM
 * geschrieben, NACHDEM die Marketing-Einwilligung per Double-Opt-in BESTÄTIGT
 * wurde. Pending-/not_given-Leads bleiben ausschließlich in unserer DB
 * (`webcheck_leads`) und erreichen das CRM nie.
 *
 * Config-gated / Trockenmodus: Ohne `CRM_WEBHOOK_URL` (bzw. `SALES_NOTIFY_URL`)
 * ist der jeweilige Effekt ein No-op mit `reason: '*-not-configured'` — der
 * Aufrufer bleibt dadurch DSGVO-sicher und der Lead geht nie verloren (er liegt
 * persistiert in der DB). Best-effort: Fehler dürfen den Nutzer-Flow nie brechen.
 */
import pino from 'pino';

const log = pino({ name: 'crm' });

export interface CrmLead {
  email: string;
  domain?: string | null;
  icpSegment?: string | null;
  source?: string | null;
  channel?: string | null;
  utmSource?: string | null;
  utmMedium?: string | null;
  utmCampaign?: string | null;
  referrer?: string | null;
}

export interface CrmConfig {
  webhookUrl: string | null;
  apiKey: string | null;
  salesNotifyUrl: string | null;
}

export function loadCrmConfig(env: NodeJS.ProcessEnv = process.env): CrmConfig {
  return {
    // Twenty REST-Upsert-Endpoint, z. B. https://crm.vectigal.tech/rest/people
    webhookUrl: env.CRM_WEBHOOK_URL || null,
    apiKey: env.CRM_API_KEY || null,
    // Bestehender Slack/Teams Incoming-Webhook (optional, graceful degrade).
    salesNotifyUrl: env.SALES_NOTIFY_URL || null,
  };
}

/**
 * Bildet einen Lead auf Twentys REST `/rest/people`-Schema ab. Bewusst nur
 * STANDARD-Felder von Twenty — unbekannte Felder würden von Twenty mit 400
 * abgelehnt. Anreicherung (icp_segment/bant/utm/consent) erfordert in Twenty
 * angelegte Custom-Fields → Folge-Issue. `domain` wird als Firmen-Hinweis im
 * Nachnamen mitgeführt, damit der Vertrieb den Scan-Bezug ohne Custom-Field sieht.
 */
export function buildTwentyPerson(lead: CrmLead): Record<string, unknown> {
  const email = String(lead.email).trim().toLowerCase();
  const localPart = email.split('@')[0] || email;
  const person: Record<string, unknown> = {
    emails: { primaryEmail: email },
    name: { firstName: localPart, lastName: lead.domain ? `(${lead.domain})` : '' },
  };
  // jobTitle ist ein Standard-Textfeld → grobe Qualifizierung ohne Custom-Field.
  if (lead.icpSegment) person.jobTitle = lead.icpSegment;
  return person;
}

async function twentyFetch(
  url: string,
  apiKey: string | null,
  init: RequestInit = {},
): Promise<{ ok: boolean; status: number; body: unknown }> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...(init.headers as Record<string, string> | undefined),
  };
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
  const res = await fetch(url, { ...init, headers });
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { ok: res.ok, status: res.status, body };
}

export interface CrmUpsertResult {
  synced: boolean;
  reason?: string;
  status?: number;
  action?: 'created' | 'exists';
}

/**
 * Upsert by email: zuerst per Filter suchen, nur bei Abwesenheit anlegen
 * (Idempotenz — derselbe Lead darf nicht duplizieren). Schlägt die Suche fehl
 * (Versions-/Filter-Inkompatibilität), wird defensiv KEIN Duplikat erzeugt,
 * sondern der Fehler gemeldet — Dedup-Sicherheit vor Vollständigkeit.
 */
export async function upsertLeadToCrm(
  lead: CrmLead,
  cfg: CrmConfig = loadCrmConfig(),
): Promise<CrmUpsertResult> {
  if (!cfg.webhookUrl) return { synced: false, reason: 'crm-not-configured' };

  const email = String(lead.email).trim().toLowerCase();
  const base = cfg.webhookUrl.replace(/\/+$/, '');

  // 1) Existiert die Person bereits? (Twenty REST Filter-Syntax)
  try {
    const filter = `emails.primaryEmail[eq]:${encodeURIComponent(email)}`;
    const found = await twentyFetch(`${base}?filter=${filter}&depth=0`, cfg.apiKey);
    if (found.ok) {
      const data = (found.body as { data?: { people?: unknown[] } } | null)?.data;
      const people = data?.people;
      if (Array.isArray(people) && people.length > 0) {
        log.info({ email }, 'CRM upsert: person already exists — skip create');
        return { synced: true, action: 'exists', status: found.status };
      }
    } else {
      // Suche nicht möglich → kein blindes Anlegen (Dedup-Schutz).
      log.warn({ status: found.status }, 'CRM upsert: lookup failed — not creating to avoid duplicates');
      return { synced: false, reason: 'crm-lookup-failed', status: found.status };
    }
  } catch (err) {
    log.error({ err: String(err) }, 'CRM upsert: lookup error');
    return { synced: false, reason: 'crm-lookup-error' };
  }

  // 2) Anlegen.
  try {
    const created = await twentyFetch(base, cfg.apiKey, {
      method: 'POST',
      body: JSON.stringify(buildTwentyPerson(lead)),
    });
    if (created.ok) {
      log.info({ email }, 'CRM upsert: person created');
      return { synced: true, action: 'created', status: created.status };
    }
    log.error({ status: created.status }, 'CRM upsert: create failed');
    return { synced: false, reason: 'crm-create-failed', status: created.status };
  } catch (err) {
    log.error({ err: String(err) }, 'CRM upsert: create error');
    return { synced: false, reason: 'crm-create-error' };
  }
}

export interface SalesNotifyResult {
  notified: boolean;
  reason?: string;
  status?: number;
}

/** Optionaler Vertriebs-Ping (Slack/Teams Incoming-Webhook). Graceful degrade. */
export async function notifySales(
  lead: CrmLead,
  cfg: CrmConfig = loadCrmConfig(),
): Promise<SalesNotifyResult> {
  if (!cfg.salesNotifyUrl) return { notified: false, reason: 'sales-notify-not-configured' };
  const text =
    `Neuer bestätigter WebCheck-Lead: ${lead.email}` +
    (lead.domain ? ` (${lead.domain})` : '') +
    (lead.icpSegment ? ` · ICP ${lead.icpSegment}` : '') +
    (lead.channel ? ` · Kanal ${lead.channel}` : '');
  try {
    const res = await fetch(cfg.salesNotifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    return { notified: res.ok, status: res.status };
  } catch (err) {
    log.error({ err: String(err) }, 'Sales notify error');
    return { notified: false, reason: 'sales-notify-error' };
  }
}
