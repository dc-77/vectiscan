/**
 * Cookieloses First-Party-Analytics (VEC-36).
 *
 * POST /api/analytics/collect nimmt anonyme Seitenaufrufe entgegen. Es werden
 * BEWUSST KEINE personenbezogenen Daten gespeichert: keine IP-Adresse, kein
 * User-Agent, kein Besucher-Identifier (vgl. Datenschutzerklaerung Abschnitt 8
 * + Regression-Gate analytics_privacy.test.ts / VEC-103). Selbst wenn der
 * Request IP/User-Agent enthaelt, werden diese nie in analytics_events
 * geschrieben — dadurch einwilligungsfrei nach § 25 Abs. 2 TTDSG.
 *
 * GET /api/analytics/summary liefert aggregierte Kennzahlen fuer das Team
 * (Admin-only).
 */
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { query } from '../lib/db.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';

const VALID_EVENT_TYPES = new Set(['pageview']);

interface CollectBody {
  path?: string;
  referrer?: string;
  eventType?: string;
  utmSource?: string;
  utmMedium?: string;
  utmCampaign?: string;
}

function clamp(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, max);
}

/**
 * Extrahiert nur die Host-Domain aus einem Referrer. Vollstaendige URLs (inkl.
 * Pfad/Query) werden NIE gespeichert, um versehentliche PII zu vermeiden.
 * Eigene Domains (Self-Referrer) werden als null behandelt.
 */
function referrerDomain(referrer: string | null): string | null {
  if (!referrer) return null;
  try {
    const host = new URL(referrer).hostname.toLowerCase();
    if (!host) return null;
    return host.slice(0, 255);
  } catch {
    return null;
  }
}

export async function analyticsRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/analytics/collect — oeffentliche, anonyme Pageview-Erfassung
  // VEC-110: Gegen DB-Write-Spam in analytics_events gedrosselt (60/min/IP).
  // Großzügiger als /api/leads (kein E-Mail-Versand), aber kappt Volumen-Abuse.
  // Überschreitung -> 429.
  server.post<{ Body: CollectBody }>(
    '/api/analytics/collect',
    { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } },
    async (request: FastifyRequest<{ Body: CollectBody }>, reply: FastifyReply) => {
      const body = request.body || ({} as CollectBody);

      const path = clamp(body.path, 512);
      if (!path || path[0] !== '/') {
        // Nur interne Pfade akzeptieren; verhindert Fremd-/Spam-Eintraege.
        return reply.status(400).send({ success: false, error: 'invalid_path' });
      }

      const eventTypeRaw = clamp(body.eventType, 48)?.toLowerCase();
      const eventType = eventTypeRaw && VALID_EVENT_TYPES.has(eventTypeRaw) ? eventTypeRaw : 'pageview';

      try {
        await query(
          `INSERT INTO analytics_events
             (event_type, path, referrer_domain, utm_source, utm_medium, utm_campaign)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [
            eventType,
            path,
            referrerDomain(clamp(body.referrer, 1024)),
            clamp(body.utmSource, 128),
            clamp(body.utmMedium, 128),
            clamp(body.utmCampaign, 128),
          ],
        );
      } catch (err) {
        request.log.error({ err }, 'Failed to record analytics event');
        // Analytics darf den Nutzerfluss nie stoeren -> 204 statt 500.
        return reply.status(204).send();
      }

      return reply.status(204).send();
    },
  );

  // GET /api/admin/analytics/summary — aggregierte Kennzahlen (Admin-only)
  // VEC-133: unter /api/admin konsolidiert, damit der Edge-Admin-Shield greift (Defense-in-Depth).
  // Der oeffentliche Beacon-Eingang bleibt POST /api/analytics/collect (kein requireAdmin).
  server.get<{ Querystring: { days?: string } }>(
    '/api/admin/analytics/summary',
    { preHandler: [requireAuth, requireAdmin] },
    async (request: FastifyRequest<{ Querystring: { days?: string } }>, reply: FastifyReply) => {
      const daysRaw = parseInt(request.query.days || '30', 10);
      const days = Number.isFinite(daysRaw) ? Math.min(Math.max(daysRaw, 1), 365) : 30;

      const totals = await query<{ total: string; pageviews: string }>(
        `SELECT COUNT(*) AS total,
                COUNT(*) FILTER (WHERE event_type = 'pageview') AS pageviews
           FROM analytics_events
          WHERE created_at >= NOW() - ($1 || ' days')::interval`,
        [String(days)],
      );

      const topPaths = await query(
        `SELECT path, COUNT(*) AS views
           FROM analytics_events
          WHERE event_type = 'pageview'
            AND created_at >= NOW() - ($1 || ' days')::interval
          GROUP BY path
          ORDER BY views DESC
          LIMIT 20`,
        [String(days)],
      );

      const topReferrers = await query(
        `SELECT referrer_domain, COUNT(*) AS views
           FROM analytics_events
          WHERE referrer_domain IS NOT NULL
            AND created_at >= NOW() - ($1 || ' days')::interval
          GROUP BY referrer_domain
          ORDER BY views DESC
          LIMIT 20`,
        [String(days)],
      );

      const topCampaigns = await query(
        `SELECT utm_source, utm_medium, utm_campaign, COUNT(*) AS views
           FROM analytics_events
          WHERE utm_source IS NOT NULL
            AND created_at >= NOW() - ($1 || ' days')::interval
          GROUP BY utm_source, utm_medium, utm_campaign
          ORDER BY views DESC
          LIMIT 20`,
        [String(days)],
      );

      return reply.send({
        success: true,
        data: {
          windowDays: days,
          total: Number(totals.rows[0]?.total || 0),
          pageviews: Number(totals.rows[0]?.pageviews || 0),
          topPaths: topPaths.rows,
          topReferrers: topReferrers.rows,
          topCampaigns: topCampaigns.rows,
        },
      });
    },
  );
}
