/**
 * WebCheck-Free — öffentlicher, anonymer Self-Service-Lead-Magnet (VEC-91 / PA-11).
 *
 * Flow (ohne Login):
 *   1. POST /api/webcheck/start  — E-Mail + Domain, Rate-Limit, Lead anlegen,
 *      Verifikations-Token + Anleitung zurück, DOI-Mail (best effort) versenden.
 *   2. POST /api/webcheck/verify — Domain-Kontrolle prüfen (Reuse VerificationService).
 *      Bei Erfolg + freiem Fenster: anonymen Customer + Order(package=webcheck)
 *      anlegen, Scan-Pipeline anstoßen. Report-Zustellung per Mail erfolgt über die
 *      bestehende PA-4-Mechanik (download_token, ws-manager handleReportComplete).
 *   3. GET  /api/webcheck/doi/confirm — Double-Opt-in Marketing-Einwilligung (DSGVO).
 *
 * SICHERHEIT: Dies ist ein öffentlicher, anonymer Endpunkt, der das Produkt
 * exponiert. Schutzmaßnahmen hier: Domain-Verifikation VOR Scan (kein Scan fremder
 * Domains), Rate-Limiting pro E-Mail/Domain/IP, genau ein Free-Scan pro verifizierter
 * Domain pro Zeitfenster, erzwungenes WebCheck-Free-Paket. Die erzeugte Order läuft
 * bewusst durch den NORMALEN Admin-Review-/Precheck-Pfad — eine vollautomatische
 * Freigabe verifizierter anonymer Scans ist eine separate Security-Entscheidung
 * (Sven), nicht der Default. Sven's Security-Sign-off ist vor Merge zwingend.
 */
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'crypto';
import pino from 'pino';
import { query, withTransaction } from '../lib/db.js';
import { generateToken, verifyAll } from '../services/VerificationService.js';
import { isValidDomain, validateTargetBatch } from '../lib/validate.js';
import { enqueuePrecheck } from '../lib/queue.js';
import { audit } from '../lib/audit.js';
import { sendWebcheckDoiEmail } from '../lib/email.js';
import { verifyCaptcha } from '../lib/captcha.js';

const log = pino({ name: 'webcheck' });

// --- Konfiguration (AC3/AC4) ---------------------------------------------------

/** Anonyme Free-Scans sind immer und ausschließlich das limitierte WebCheck-Paket. */
export const WEBCHECK_PACKAGE = 'webcheck' as const;

/** Genau 1 Free-Scan pro verifizierter Domain in diesem Fenster (AC3). */
export const FREE_SCAN_WINDOW_HOURS = 24;

/** Rate-Limit-Schwellen pro Bezeichner im Fenster (AC4). */
export const RATE_LIMITS = {
  windowMinutes: 60,
  maxPerEmail: 3,
  maxPerDomain: 3,
  maxPerIp: 5,
} as const;

/**
 * Aggregierte Velocity-Schwellen (VEC-173, F2 aus VEC-169).
 *
 * Die per-E-Mail/Domain/IP-Limits (RATE_LIMITS) greifen pro Bezeichner und sind
 * per IP-Rotation umgehbar: ein Angreifer kann viele verschiedene Opferadressen
 * mit je 1 Mail bombardieren → Mail-Amplification / Spam-Relay. Diese Schwellen
 * greifen AGGREGIERT (global + pro Empfänger-Mail-Domain) und kappen den Blast
 * Radius unabhängig von der Quell-IP. Eine erreichte Schwelle ist zugleich ein
 * alertbares Ereignis (`webcheck.velocity_alert` im audit_log → Grafana-Spike).
 *
 * Fenster bewusst auf RATE_LIMITS.windowMinutes (60min) ausgerichtet, damit beide
 * Zählungen in EINER DB-Abfrage laufen. Konservativ dimensioniert; post-Launch
 * anhand der realen Velocity-Metriken nachzuschärfen.
 */
export const VELOCITY = {
  /** Gesamt-DOI-Mails über ALLE Leads pro Fenster. */
  maxGlobal: 200,
  /** DOI-Mails an EINE Empfänger-Mail-Domain (z.B. gmail.com) pro Fenster. */
  maxPerRecipientDomain: 25,
} as const;

/** Empfänger-Mail-Domain (Teil nach dem letzten '@'), bereits normalisiert. */
export function recipientDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1) : '';
}

/**
 * Velocity-Entscheidung (pure): `limited` = aggregierte Schwelle erreicht,
 * `reasons` benennt die ausgelösten Achsen für das Alert-Detail.
 */
export function decideVelocityAlert(counts: {
  global: number;
  recipientDomain: number;
}): { limited: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (counts.global >= VELOCITY.maxGlobal) reasons.push('global');
  if (counts.recipientDomain >= VELOCITY.maxPerRecipientDomain) {
    reasons.push('recipient_domain');
  }
  return { limited: reasons.length > 0, reasons };
}

// --- Pure Helfer (unit-testbar ohne DB) ---------------------------------------

// Konservative, längen-begrenzte E-Mail-Prüfung. Bewusst streng, da öffentlich.
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

export function isValidEmail(email: unknown): email is string {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim();
  if (trimmed.length === 0 || trimmed.length > 254) return false;
  return EMAIL_REGEX.test(trimmed);
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Rate-Limit-Entscheidung (pure): true = drosseln. Schwelle ist erreicht, wenn die
 * Zahl der bestehenden Einträge im Fenster >= Maximum ist (der neue Versuch wäre der
 * (count+1)-te). Getrennt pro E-Mail/Domain/IP — der strengste Treffer gewinnt.
 */
export function decideRateLimited(counts: {
  email: number;
  domain: number;
  ip: number;
}): boolean {
  return (
    counts.email >= RATE_LIMITS.maxPerEmail ||
    counts.domain >= RATE_LIMITS.maxPerDomain ||
    counts.ip >= RATE_LIMITS.maxPerIp
  );
}

/** UTM-/Quellfelder defensiv aus dem Request-Body extrahieren (AC7). */
export function extractCapture(body: Record<string, unknown>): Record<string, string | null> {
  const pick = (v: unknown): string | null =>
    typeof v === 'string' && v.trim().length > 0 ? v.trim().slice(0, 255) : null;
  return {
    source: pick(body.source),
    channel: pick(body.channel),
    utm_source: pick(body.utm_source),
    utm_medium: pick(body.utm_medium),
    utm_campaign: pick(body.utm_campaign),
    utm_term: pick(body.utm_term),
    utm_content: pick(body.utm_content),
    referrer: pick(body.referrer),
    icp_segment: pick(body.icp_segment),
  };
}

/**
 * Marketing-Einwilligung defensiv aus dem Request-Body lesen (AC5, VEC-173).
 *
 * DSGVO-Kopplungsverbot: Die Einwilligung gilt NUR als erteilt, wenn der Body
 * `marketing_consent === true` (strikt boolesch) trägt — Default ist „keine
 * Einwilligung". Die Consent-Text-Version wird ausschließlich bei erteilter
 * Einwilligung übernommen (ein Versions-String ohne Einwilligung ist als
 * Nachweis bedeutungslos).
 */
export function parseConsent(body: Record<string, unknown>): {
  marketingConsent: boolean;
  consentTextVersion: string | null;
} {
  const marketingConsent = body.marketing_consent === true;
  const raw = body.consent_text_version;
  const consentTextVersion =
    marketingConsent && typeof raw === 'string' && raw.trim().length > 0
      ? raw.trim().slice(0, 64)
      : null;
  return { marketingConsent, consentTextVersion };
}

/** Verifikations-Anleitung für AC2 (DNS-TXT / Datei / Meta-Tag). */
export function buildVerifyInstructions(domain: string, token: string) {
  return {
    token,
    methods: [
      { type: 'dns_txt', record: `_vectiscan-verify.${domain}`, value: token },
      { type: 'file', path: `https://${domain}/.well-known/vectiscan-verify.txt`, value: token },
      { type: 'meta_tag', value: `<meta name="vectiscan-verify" content="${token}">` },
    ],
  };
}

// --- Routen --------------------------------------------------------------------

interface StartBody {
  email?: unknown;
  domain?: unknown;
  [k: string]: unknown;
}

interface VerifyBody {
  leadId?: unknown;
}

interface DoiQuery {
  token?: string;
}

export async function webcheckRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/webcheck/start — anonym (AC1, AC4, AC5-DOI-Start, AC7)
  server.post<{ Body: StartBody }>('/api/webcheck/start', async (request, reply) => {
    const body = (request.body || {}) as StartBody;

    if (!isValidEmail(body.email)) {
      return reply.status(400).send({ success: false, error: 'invalid_email' });
    }
    if (!isValidDomain(body.domain)) {
      return reply.status(400).send({ success: false, error: 'invalid_domain' });
    }

    const email = normalizeEmail(body.email as string);
    const domain = normalizeDomain(body.domain as string);
    const ip = request.ip;
    const win = `${RATE_LIMITS.windowMinutes} minutes`;

    // CAPTCHA (Proof-of-Humanity) VOR jeglichem DB-Schreibzugriff/DOI-Versand
    // (VEC-173, F2). Env-gated: ohne WEBCHECK_TURNSTILE_SECRET deaktiviert, sonst
    // fail-closed. Akzeptiert `captchaToken` oder den Turnstile-Default-Feldnamen.
    const captchaToken =
      typeof body.captchaToken === 'string'
        ? body.captchaToken
        : body['cf-turnstile-response'];
    const captcha = await verifyCaptcha(captchaToken, ip);
    if (!captcha.ok) {
      audit({ orderId: null, action: 'webcheck.captcha_failed', details: { domain }, ip });
      return reply.status(403).send({ success: false, error: 'captcha_failed' });
    }

    // Rate-Limit-Fensterzählung pro E-Mail/Domain/IP (AC4) + aggregierte
    // Velocity-Zählung global/Empfänger-Mail-Domain (VEC-173, F2) in EINER Abfrage.
    const counts = await query<{
      email_count: string;
      domain_count: string;
      ip_count: string;
      global_count: string;
      recipient_domain_count: string;
    }>(
      `SELECT
         COUNT(*) FILTER (WHERE email = $1) AS email_count,
         COUNT(*) FILTER (WHERE domain = $2) AS domain_count,
         COUNT(*) FILTER (WHERE ip = $3) AS ip_count,
         COUNT(*) AS global_count,
         COUNT(*) FILTER (WHERE split_part(email, '@', 2) = $4) AS recipient_domain_count
       FROM webcheck_leads
       WHERE created_at > NOW() - INTERVAL '${win}'`,
      [email, domain, ip, recipientDomain(email)],
    );
    const c = counts.rows[0];
    if (
      decideRateLimited({
        email: Number(c?.email_count ?? 0),
        domain: Number(c?.domain_count ?? 0),
        ip: Number(c?.ip_count ?? 0),
      })
    ) {
      audit({ orderId: null, action: 'webcheck.rate_limited', details: { domain }, ip });
      return reply.status(429).send({ success: false, error: 'rate_limited' });
    }

    // Aggregierte Velocity-Schwelle (VEC-173, F2): alertbares Spike-Ereignis +
    // harte Drosselung gegen IP-Rotations-Mail-Amplification.
    const velocity = decideVelocityAlert({
      global: Number(c?.global_count ?? 0),
      recipientDomain: Number(c?.recipient_domain_count ?? 0),
    });
    if (velocity.limited) {
      const alertDetails = {
        reasons: velocity.reasons,
        recipientDomain: recipientDomain(email),
        globalCount: Number(c?.global_count ?? 0),
        recipientDomainCount: Number(c?.recipient_domain_count ?? 0),
      };
      // Stabiler Log-Marker für Loki/Grafana-Spike-Alert (siehe MONITORING.md);
      // audit_log hält dieselbe Evidenz DB-seitig für Forensik.
      log.warn({ event: 'webcheck_velocity_alert', ...alertDetails }, 'WebCheck velocity threshold reached');
      audit({ orderId: null, action: 'webcheck.velocity_alert', details: alertDetails, ip });
      return reply.status(429).send({ success: false, error: 'velocity_limited' });
    }

    const verificationToken = generateToken();
    const cap = extractCapture(body);

    // DSGVO-Kopplungsverbot (VEC-173): Marketing-DOI ist strikt von der Scan-
    // Erbringung entkoppelt. Nur bei `marketing_consent === true` wird ein
    // DOI-Token erzeugt, consent_status='pending' gesetzt und die DOI-Mail
    // versendet. Ohne Einwilligung entsteht der Lead allein für den Scan
    // (consent_status='declined', legal_basis='none'), keine Marketing-Mail.
    const { marketingConsent, consentTextVersion } = parseConsent(body);
    const doiToken = marketingConsent ? crypto.randomUUID() : null;

    const insert = await query<{ id: string }>(
      `INSERT INTO webcheck_leads
         (email, domain, verification_token, doi_token, doi_sent_at, ip,
          source, channel, utm_source, utm_medium, utm_campaign, utm_term,
          utm_content, referrer, icp_segment,
          marketing_consent, consent_text_version, consent_status, legal_basis)
       VALUES ($1,$2,$3,$4,
          CASE WHEN $15::boolean THEN NOW() ELSE NULL END,
          $5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
          $15,$16,
          CASE WHEN $15::boolean THEN 'pending' ELSE 'declined' END,
          CASE WHEN $15::boolean THEN 'consent_doi' ELSE 'none' END)
       RETURNING id`,
      [
        email, domain, verificationToken, doiToken, ip,
        cap.source, cap.channel, cap.utm_source, cap.utm_medium, cap.utm_campaign,
        cap.utm_term, cap.utm_content, cap.referrer, cap.icp_segment,
        marketingConsent, consentTextVersion,
      ],
    );
    const leadId = insert.rows[0].id;

    audit({
      orderId: null,
      action: 'webcheck.lead_created',
      details: { leadId, domain, marketingConsent },
      ip,
    });

    // DOI-Mail NUR bei erteilter Marketing-Einwilligung (Kopplungsverbot, UWG §7).
    // Copy/Rechtsgrundlagentext final von Greta (CMO/DSGVO) geliefert (VEC-91-Child).
    if (marketingConsent && doiToken) {
      await sendWebcheckDoiEmail(email, domain, doiToken);
    }

    return reply.status(201).send({
      success: true,
      data: {
        leadId,
        domain,
        verification: buildVerifyInstructions(domain, verificationToken),
      },
    });
  });

  // POST /api/webcheck/verify — anonym (AC2, AC3)
  server.post<{ Body: VerifyBody }>('/api/webcheck/verify', async (request, reply) => {
    const leadId = (request.body || ({} as VerifyBody)).leadId;
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (typeof leadId !== 'string' || !UUID_REGEX.test(leadId)) {
      return reply.status(400).send({ success: false, error: 'invalid_lead_id' });
    }

    const leadRes = await query<{
      id: string; email: string; domain: string; verification_token: string;
      verified: boolean; order_id: string | null;
    }>(
      `SELECT id, email, domain, verification_token, verified, order_id
       FROM webcheck_leads WHERE id = $1`,
      [leadId],
    );
    if (leadRes.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'lead_not_found' });
    }
    const lead = leadRes.rows[0];

    // Idempotenz: bereits angestoßener Scan → kein zweiter (AC3).
    if (lead.order_id) {
      return reply.send({
        success: true,
        data: { verified: true, scanStarted: false, alreadyRequested: true, orderId: lead.order_id },
      });
    }

    // AC2: Domain-Kontrolle nachweisen (kein Scan fremder Domains).
    const verification = await verifyAll(lead.domain, lead.verification_token);
    if (!verification.verified) {
      return reply.send({ success: true, data: { verified: false, scanStarted: false } });
    }

    await query(
      `UPDATE webcheck_leads
       SET verified = TRUE, verified_at = NOW(), verification_method = $2, updated_at = NOW()
       WHERE id = $1`,
      [lead.id, verification.method],
    );

    // Ziel-Validierung VOR dem Lock (rein CPU-seitig, kein Grund den Lock zu halten).
    const batch = validateTargetBatch([{ raw_input: lead.domain }]);
    if (batch.errors.length > 0 || batch.targets.some((t) => !t.valid)) {
      return reply.status(400).send({ success: false, error: 'target_validation_failed' });
    }
    const t = batch.targets[0];

    // AC3 + TOCTOU-Guard (VEC-174): Fenster-Prüfung und Order-Anlage laufen ATOMAR
    // unter einem per-Domain Advisory-Lock. Zwei nebenläufige Verifies derselben
    // Domain (zwei Leads, gleicher Eigentümer) werden serialisiert — der zweite
    // sieht den `scan_started_at` des ersten und wird abgewiesen, statt dass beide
    // den COUNT==0-Check passieren und zwei Free-Scans anstoßen. Der xact-Lock wird
    // automatisch bei COMMIT/ROLLBACK freigegeben. `verifyAll()` (Netz-I/O) liegt
    // bewusst VOR der Transaktion, damit der Lock nicht über langsame I/O hält.
    const gate = await withTransaction(async (q) => {
      // Namespaced 2-Key-Advisory-Lock (Klasse 'webcheck_free_scan_domain') →
      // serialisiert pro Domain ohne mit anderen Advisory-Locks zu kollidieren.
      await q(`SELECT pg_advisory_xact_lock(hashtext('webcheck_free_scan_domain'), hashtext($1))`, [lead.domain]);

      // AC3: genau 1 Free-Scan pro verifizierter Domain im Fenster — jetzt rennfest.
      const recent = await q<{ count: string }>(
        `SELECT COUNT(*) AS count FROM webcheck_leads
         WHERE domain = $1 AND scan_started_at IS NOT NULL
           AND scan_started_at > NOW() - INTERVAL '${FREE_SCAN_WINDOW_HOURS} hours'`,
        [lead.domain],
      );
      if (Number(recent.rows[0]?.count ?? 0) > 0) {
        return { limited: true as const };
      }

      // Anonymen Customer + Order(package=webcheck) anlegen → Report-Mail via PA-4.
      const customerRes = await q<{ id: string }>(
        `INSERT INTO customers (email) VALUES ($1)
         ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id`,
        [lead.email],
      );
      const customerId = customerRes.rows[0].id;

      const orderRes = await q<{ id: string }>(
        `INSERT INTO orders (customer_id, target_url, package, status, target_count)
         VALUES ($1, $2, $3, 'precheck_running', 1) RETURNING id`,
        [customerId, t.canonical, WEBCHECK_PACKAGE],
      );
      const orderId = orderRes.rows[0].id;

      const targetRes = await q<{ id: string }>(
        `INSERT INTO scan_targets
           (order_id, raw_input, canonical, target_type, discovery_policy, status)
         VALUES ($1, $2, $3, $4, $5, 'pending_precheck') RETURNING id`,
        [orderId, t.raw_input, t.canonical, t.target_type, t.policy_default],
      );

      // Den Free-Scan-Verbrauch innerhalb derselben Transaktion festschreiben — der
      // wartende zweite Verify sieht ihn erst nach COMMIT und damit garantiert.
      await q(
        `UPDATE webcheck_leads SET order_id = $2, scan_started_at = NOW(), updated_at = NOW()
         WHERE id = $1`,
        [lead.id, orderId],
      );

      return { limited: false as const, orderId, targetId: targetRes.rows[0].id };
    });

    if (gate.limited) {
      audit({ orderId: null, action: 'webcheck.free_scan_window_hit', details: { domain: lead.domain }, ip: request.ip });
      return reply.status(429).send({
        success: false,
        error: 'free_scan_already_used',
        data: { windowHours: FREE_SCAN_WINDOW_HOURS },
      });
    }

    audit({
      orderId: gate.orderId,
      action: 'webcheck.scan_requested',
      details: { leadId: lead.id, domain: lead.domain, method: verification.method },
      ip: request.ip,
    });

    await enqueuePrecheck({ orderId: gate.orderId, targetIds: [gate.targetId] });

    return reply.send({
      success: true,
      data: { verified: true, scanStarted: true, orderId: gate.orderId },
    });
  });

  // GET /api/webcheck/doi/confirm?token=... — Double-Opt-in (AC5, DSGVO)
  server.get<{ Querystring: DoiQuery }>('/api/webcheck/doi/confirm', async (request, reply) => {
    const token = request.query?.token;
    if (!token || typeof token !== 'string') {
      return reply.status(400).send({ success: false, error: 'invalid_token' });
    }

    const res = await query<{ id: string }>(
      `UPDATE webcheck_leads
       SET consent_status = 'confirmed', doi_confirmed_at = NOW(), updated_at = NOW()
       WHERE doi_token = $1 AND consent_status = 'pending'
       RETURNING id`,
      [token],
    );
    if (res.rows.length === 0) {
      // Bereits bestätigt oder unbekannt — idempotent, kein Leak ob Token existiert.
      return reply.send({ success: true, data: { confirmed: false } });
    }

    audit({ orderId: null, action: 'webcheck.doi_confirmed', details: { leadId: res.rows[0].id }, ip: request.ip });
    return reply.send({ success: true, data: { confirmed: true } });
  });
}
