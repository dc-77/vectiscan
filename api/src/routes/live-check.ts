/**
 * Live-Check (SofortScan) — Auth-Fassade `/api/live-check/*` (VEC-363).
 *
 * Kapselt den internen `webcheck-core`-Microservice. Jede Route erzwingt:
 *   - Auth (eingeloggter Nutzer, Rolle `customer` — Admin separat erlaubt),
 *   - Modul-Allowlist (Default-Deny, nur BEHALTEN-Module aus VEC-360 §7),
 *   - Target-Validierung mit SSRF-Schutz (RFC1918/Loopback/Cloud-Metadata),
 *   - pro-User-Rate-Limit + Concurrency-Cap,
 *   - Scan-Audit-Log (wer/was/wann) in live_check_audit.
 *
 * Upstream-Antworten werden ins `{ success, data }`-Schema normalisiert; der
 * Upstream-Host (`webcheck-core`) ist intern und vertrauenswürdig, daher wird
 * der Aufruf NICHT durch den SSRF-Guard geschickt (der würde interne Hosts
 * gerade blocken) — der SSRF-Guard greift ausschließlich auf das vom Nutzer
 * gewählte Scan-Ziel.
 */
import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import pino from 'pino';
import { query } from '../lib/db.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import {
  LIVE_CHECK_MODULES,
  getLiveCheckModule,
  checkTarget,
  toUpstreamTarget,
  type TargetCheckResult,
} from '../lib/liveCheck.js';
import { LiveCheckLimiter } from '../lib/liveCheckLimiter.js';
import {
  summarizeAbuse,
  type LiveCheckAuditRow,
  type LiveCheckAuditStatus,
} from '../lib/liveCheckAbuse.js';

const log = pino({ name: 'live-check' });

/** Basis-URL des internen webcheck-core-Service (nur internes Netz). */
const CORE_URL = process.env.WEBCHECK_CORE_URL ?? 'http://webcheck-core:3000';

/** Obergrenze für die Upstream-Antwortzeit pro Modul. */
const UPSTREAM_TIMEOUT_MS = Number(process.env.WEBCHECK_CORE_TIMEOUT_MS ?? 25_000);

type LiveCheckStatus = 'ok' | 'blocked' | 'rate_limited' | 'upstream_error' | 'invalid';

/** Fire-and-forget Audit-Eintrag in live_check_audit. */
async function auditLiveCheck(entry: {
  userId: string | null;
  customerId: string | null;
  module: string;
  target: string;
  targetIp?: string | null;
  status: LiveCheckStatus;
  detail?: string | null;
  ip?: string | null;
}): Promise<void> {
  try {
    await query(
      `INSERT INTO live_check_audit
         (user_id, customer_id, module, target, target_ip, status, detail, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        entry.userId,
        entry.customerId,
        entry.module.slice(0, 50),
        entry.target.slice(0, 255),
        entry.targetIp ?? null,
        entry.status,
        entry.detail ? entry.detail.slice(0, 500) : null,
        entry.ip ?? null,
      ],
    );
  } catch (err) {
    log.error({ err, module: entry.module }, 'Failed to write live_check_audit');
  }
}

const limiter = new LiveCheckLimiter();

export async function liveCheckRoutes(server: FastifyInstance): Promise<void> {
  // Modul-Katalog für die UI (VEC-366): zeigt nur freigeschaltete Module.
  server.get(
    '/api/live-check/modules',
    { preHandler: requireAuth },
    async (_request: FastifyRequest, reply: FastifyReply) => {
      return reply.send({
        success: true,
        data: {
          modules: LIVE_CHECK_MODULES.map((m) => ({
            key: m.key,
            label: m.label,
            group: m.group,
          })),
        },
      });
    },
  );

  // Einzelnes Modul gegen ein Ziel ausführen.
  server.get(
    '/api/live-check/run/:module',
    { preHandler: requireAuth },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const user = request.user;
      // requireAuth garantiert user; defensiv prüfen.
      if (!user) {
        return reply.status(401).send({ success: false, error: 'Authentication required' });
      }
      // Nur Kunden (und Admins) dürfen Live-Checks fahren.
      if (user.role !== 'customer' && user.role !== 'admin') {
        return reply.status(403).send({ success: false, error: 'forbidden' });
      }

      const { module: moduleKey } = request.params as { module: string };
      const rawTarget = (request.query as Record<string, string>)?.target ?? '';
      const clientIp = request.ip ?? null;

      // 1. Modul-Allowlist (Default-Deny).
      const mod = getLiveCheckModule(moduleKey);
      if (!mod) {
        return reply.status(404).send({ success: false, error: 'unknown_module' });
      }

      // 2. Rate-Limit + Concurrency-Cap (vor jeder Auflösung/Upstream-Arbeit).
      const acquired = limiter.acquire(user.sub);
      if (!acquired.ok) {
        await auditLiveCheck({
          userId: user.sub,
          customerId: user.customerId,
          module: mod.key,
          target: String(rawTarget).slice(0, 255),
          status: 'rate_limited',
          detail: acquired.reason,
          ip: clientIp,
        });
        return reply
          .status(429)
          .send({ success: false, error: acquired.reason, retryAfter: acquired.retryAfterSec });
      }

      try {
        // 3. Target-Validierung + SSRF-Härtung.
        let target: TargetCheckResult;
        try {
          target = await checkTarget(rawTarget);
        } catch (err) {
          log.error({ err }, 'checkTarget threw');
          target = { ok: false, reason: 'resolve_failed', message: 'Ziel konnte nicht geprüft werden.' };
        }
        if (!target.ok || !target.host) {
          const status: LiveCheckStatus = target.reason === 'ssrf_blocked' ? 'blocked' : 'invalid';
          await auditLiveCheck({
            userId: user.sub,
            customerId: user.customerId,
            module: mod.key,
            target: String(rawTarget).slice(0, 255),
            status,
            detail: target.reason,
            ip: clientIp,
          });
          return reply
            .status(status === 'blocked' ? 403 : 400)
            .send({ success: false, error: status === 'blocked' ? 'target_blocked' : 'invalid_target', message: target.message });
        }

        // 4. Upstream-Aufruf an webcheck-core (interner, vertrauenswürdiger Host).
        // VEC-411: schema-qualifizierter Ziel-Param — sonst werfen Upstream-
        // Module mit `new URL()` (ssl/tls/headers/…) auf nacktem Hostnamen.
        const upstreamUrl = `${CORE_URL}/api/${mod.upstream}?url=${encodeURIComponent(toUpstreamTarget(target.host))}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
        let data: unknown;
        try {
          const res = await fetch(upstreamUrl, {
            method: 'GET',
            signal: controller.signal,
            headers: { Accept: 'application/json' },
          });
          const bodyText = await res.text();
          let parsed: unknown = bodyText;
          try {
            parsed = JSON.parse(bodyText);
          } catch {
            // Upstream lieferte kein JSON → als Roh-Text durchreichen.
          }
          if (!res.ok) {
            await auditLiveCheck({
              userId: user.sub,
              customerId: user.customerId,
              module: mod.key,
              target: target.host,
              targetIp: target.resolvedIp,
              status: 'upstream_error',
              detail: `status=${res.status}`,
              ip: clientIp,
            });
            return reply.status(502).send({
              success: false,
              error: 'upstream_error',
              data: { module: mod.key, status: res.status },
            });
          }
          // Upstream-Module signalisieren Fehler teils als { error: "..." } mit 200.
          if (parsed && typeof parsed === 'object' && 'error' in (parsed as Record<string, unknown>)) {
            await auditLiveCheck({
              userId: user.sub,
              customerId: user.customerId,
              module: mod.key,
              target: target.host,
              targetIp: target.resolvedIp,
              status: 'upstream_error',
              detail: String((parsed as Record<string, unknown>).error).slice(0, 200),
              ip: clientIp,
            });
            return reply.status(502).send({
              success: false,
              error: 'upstream_error',
              data: { module: mod.key },
            });
          }
          data = parsed;
        } catch (err) {
          const aborted = (err as Error)?.name === 'AbortError';
          await auditLiveCheck({
            userId: user.sub,
            customerId: user.customerId,
            module: mod.key,
            target: target.host,
            targetIp: target.resolvedIp,
            status: 'upstream_error',
            detail: aborted ? 'timeout' : 'fetch_failed',
            ip: clientIp,
          });
          return reply
            .status(aborted ? 504 : 502)
            .send({ success: false, error: aborted ? 'upstream_timeout' : 'upstream_unreachable' });
        } finally {
          clearTimeout(timer);
        }

        // 5. Erfolg: normalisieren + auditieren.
        await auditLiveCheck({
          userId: user.sub,
          customerId: user.customerId,
          module: mod.key,
          target: target.host,
          targetIp: target.resolvedIp,
          status: 'ok',
          ip: clientIp,
        });
        return reply.send({
          success: true,
          data: { module: mod.key, label: mod.label, target: target.host, result: data },
        });
      } finally {
        limiter.release(user.sub);
      }
    },
  );

  // Abuse-Monitoring (VEC-368, §6): read-only Admin-Auswertung über
  // live_check_audit. Verdichtet das Audit-Log zu Abuse-Signalen pro Akteur
  // (User/IP) über ein konfigurierbares Zeitfenster. Kein State, kein Schreiben.
  server.get(
    '/api/admin/live-check/abuse',
    { preHandler: [requireAuth, requireAdmin] },
    async (request: FastifyRequest, reply: FastifyReply) => {
      const q = request.query as Record<string, string>;
      // Fenster in Stunden, geklemmt auf [1, 720] (max. 30 Tage).
      const hours = Math.min(720, Math.max(1, Number(q?.hours) || 24));
      // Akteurs-Cap für die Antwort.
      const topN = Math.min(500, Math.max(1, Number(q?.top) || 50));

      const rows = await query<{
        user_id: string | null;
        ip_address: string | null;
        status: string;
      }>(
        `SELECT user_id, ip_address::text AS ip_address, status
           FROM live_check_audit
          WHERE created_at >= NOW() - ($1 || ' hours')::interval`,
        [String(hours)],
      );

      const auditRows: LiveCheckAuditRow[] = rows.rows.map((r) => ({
        userId: r.user_id,
        ip: r.ip_address,
        status: r.status as LiveCheckAuditStatus,
      }));

      const summary = summarizeAbuse(auditRows, { topN });
      return reply.send({
        success: true,
        data: { windowHours: hours, ...summary },
      });
    },
  );
}
