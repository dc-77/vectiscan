/**
 * Lead-Capture / Demo-Anfragen (VEC-36).
 *
 * Oeffentliches POST /api/leads nimmt Anfragen aus dem Demo-Formular entgegen.
 * Ablauf ("Leads landen verlaesslich beim Vertrieb"):
 *   1. Lead wird in der DB persistiert (routing_status = 'pending').
 *   2. Routing-E-Mail an den Vertrieb wird versucht.
 *   3. routing_status -> 'routed' (Erfolg) bzw. 'failed' (E-Mail aus/Fehler).
 *      Bei 'failed' ist der Lead trotzdem sicher gespeichert und ueber
 *      GET /api/leads (Admin) abrufbar — kein Lead geht verloren.
 *
 * GET /api/leads listet eingegangene Leads fuer den Vertrieb (Admin-only).
 */
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { query } from '../lib/db.js';
import { sendDemoLeadEmail } from '../lib/email.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';

// Bewusst pragmatische E-Mail-Validierung (kein RFC-5322-Parser).
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const VALID_PACKAGES = new Set([
  'webcheck',
  'perimeter',
  'compliance',
  'supplychain',
  'insurance',
  'unsure',
]);

interface LeadBody {
  name?: string;
  email?: string;
  company?: string;
  phone?: string;
  targetDomain?: string;
  packageInterest?: string;
  message?: string;
  consent?: boolean;
  utmSource?: string;
  utmMedium?: string;
  utmCampaign?: string;
  referrer?: string;
  // Honeypot (VEC-110): unsichtbares Feld; echte Nutzer füllen es nie aus.
  website?: string;
}

// Schneidet Strings auf die DB-Spaltenlaenge und trimmt Leerzeichen.
function clamp(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, max);
}

export async function leadRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/leads — oeffentliche Lead-Annahme (Demo-Formular)
  // VEC-110: Eng gedrosselt (5/min/IP), da jeder Request eine ausgehende
  // Resend-E-Mail triggert (Amplification). Überschreitung -> 429.
  server.post<{ Body: LeadBody }>(
    '/api/leads',
    { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } },
    async (request: FastifyRequest<{ Body: LeadBody }>, reply: FastifyReply) => {
      const body = request.body || ({} as LeadBody);

      // Honeypot (VEC-110): Bots füllen tendenziell alle Felder aus. Ist das
      // versteckte Feld gesetzt, akzeptieren wir scheinbar (200), persistieren
      // aber nichts und versenden keine E-Mail — ohne dem Bot ein Signal zu geben.
      if (typeof body.website === 'string' && body.website.trim() !== '') {
        request.log.warn('Lead honeypot triggered — silently dropped');
        return reply.send({ success: true, data: { id: null, routed: false } });
      }

      const email = clamp(body.email, 255);
      if (!email || !EMAIL_REGEX.test(email)) {
        return reply.status(400).send({ success: false, error: 'invalid_email' });
      }

      // DSGVO: Kontaktaufnahme nur mit ausdruecklicher Einwilligung.
      if (body.consent !== true) {
        return reply.status(400).send({ success: false, error: 'consent_required' });
      }

      const packageInterestRaw = clamp(body.packageInterest, 64);
      const packageInterest =
        packageInterestRaw && VALID_PACKAGES.has(packageInterestRaw.toLowerCase())
          ? packageInterestRaw.toLowerCase()
          : null;

      const lead = {
        name: clamp(body.name, 255),
        email,
        company: clamp(body.company, 255),
        phone: clamp(body.phone, 64),
        targetDomain: clamp(body.targetDomain, 255),
        packageInterest,
        message: clamp(body.message, 4000),
        utmSource: clamp(body.utmSource, 128),
        utmMedium: clamp(body.utmMedium, 128),
        utmCampaign: clamp(body.utmCampaign, 128),
        referrer: clamp(body.referrer, 512),
      };

      let leadId: string;
      try {
        const inserted = await query<{ id: string }>(
          `INSERT INTO leads
             (name, email, company, phone, target_domain, package_interest, message,
              source, utm_source, utm_medium, utm_campaign, referrer, consent, routing_status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,'demo_form',$8,$9,$10,$11,TRUE,'pending')
           RETURNING id`,
          [
            lead.name,
            lead.email,
            lead.company,
            lead.phone,
            lead.targetDomain,
            lead.packageInterest,
            lead.message,
            lead.utmSource,
            lead.utmMedium,
            lead.utmCampaign,
            lead.referrer,
          ],
        );
        leadId = inserted.rows[0].id;
      } catch (err) {
        request.log.error({ err }, 'Failed to persist lead');
        return reply.status(500).send({ success: false, error: 'lead_persist_failed' });
      }

      // E-Mail-Routing an den Vertrieb. Der Lead ist bereits sicher gespeichert,
      // daher darf ein Fehler hier die Annahme nicht scheitern lassen.
      const routed = await sendDemoLeadEmail({ id: leadId, ...lead });

      try {
        await query(
          `UPDATE leads
             SET routing_status = $2,
                 routed_at = CASE WHEN $2 = 'routed' THEN NOW() ELSE routed_at END
           WHERE id = $1`,
          [leadId, routed ? 'routed' : 'failed'],
        );
      } catch (err) {
        request.log.error({ err, leadId }, 'Failed to update lead routing_status');
      }

      return reply.send({ success: true, data: { id: leadId, routed } });
    },
  );

  // GET /api/admin/leads — Vertriebssicht auf eingegangene Leads (Admin-only)
  // VEC-133: unter /api/admin konsolidiert, damit der Edge-Admin-Shield greift (Defense-in-Depth).
  // Der oeffentliche Lead-Eingang bleibt POST /api/leads (kein requireAdmin).
  server.get(
    '/api/admin/leads',
    { preHandler: [requireAuth, requireAdmin] },
    async (_request: FastifyRequest, reply: FastifyReply) => {
      const result = await query(
        `SELECT id, name, email, company, phone, target_domain, package_interest,
                message, source, utm_source, utm_medium, utm_campaign, referrer,
                routing_status, routed_at, created_at
           FROM leads
          ORDER BY created_at DESC
          LIMIT 500`,
      );
      return reply.send({ success: true, data: { leads: result.rows } });
    },
  );
}
