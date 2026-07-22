import { FastifyInstance, FastifyReply } from 'fastify';
import { query } from '../lib/db.js';
import { scanQueue, reportQueue, publishEvent, getProgressFromRedis, enqueuePrecheck } from '../lib/queue.js';
import { minioClient } from '../lib/minio.js';
import { isValidDomain, isValidTarget, validateTargetBatch } from '../lib/validate.js';
import { generateToken } from '../services/VerificationService.js';
import { verifyJwt } from '../lib/auth.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { requireAdmin } from '../middleware/requireAdmin.js';
import { audit } from '../lib/audit.js';
import {
  normalizeSeverityCounts,
  sumSeverityCounts,
  reconcileSeverityCounts,
} from '../lib/severityCounts.js';
// VEC-289: kanonischer Paket-Katalog (single source of truth).
import { PACKAGE_KEYS, getPackage, isPackageKey, type PackageKey } from '../lib/catalog.generated.js';
// VEC-436: Stripe Einzelscan-Checkout (mode=payment).
import {
  isStripeConfigured,
  getStripe,
  getOneTimePriceIdForPackage,
  isOneTimePurchasable,
  getOrderCheckoutUrls,
} from '../lib/stripe.js';

// Report-Download-TTL (VEC-180/VEC-197): 30 Tage. Spiegelt den Worter-Default
// (report-worker/reporter/worker.py: now + 30d Worker-Default) und Migration 034 (DB-DEFAULT).
// Wird als effektiver Ablauf für Legacy-Zeilen ohne gesetztes expires_at genutzt.
const REPORT_DOWNLOAD_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// A7 (Migration 044): SELECT-Varianten fuer den results-Endpoint. Die A7-
// Variante liest status/skip_reason mit; die Legacy-Variante laesst sie weg und
// dient als 42703-Fallback, falls Migration 044 beim Boot durchfiel (siehe
// GET /api/orders/:id/results). Die Spaltenliste bis exit_code/duration_ms/
// created_at ist in beiden identisch, damit die camelCase-Mappung unveraendert
// greift (fehlende status/skip_reason -> null).
const RESULTS_SELECT_A7 =
  `SELECT id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms,
          status, skip_reason, created_at
   FROM scan_results
   WHERE order_id = $1
   ORDER BY phase ASC, created_at ASC`;
const RESULTS_SELECT_LEGACY =
  `SELECT id, host_ip, phase, tool_name, raw_output, exit_code, duration_ms,
          created_at
   FROM scan_results
   WHERE order_id = $1
   ORDER BY phase ASC, created_at ASC`;

async function streamReport(reply: FastifyReply, report: Record<string, unknown>) {
  const bucket = report.minio_bucket as string;
  const objectPath = report.minio_path as string;
  const domain = report.target_url as string;
  const recordedSize = report.file_size_bytes as number;
  const createdAt = report.created_at as Date;
  const pkg = (report.package as string) || 'perimeter';
  const version = (report.version as number) || 1;

  const dateStr = createdAt.toISOString().slice(0, 10);
  const timeStr = createdAt.toISOString().slice(11, 16).replace(':', '');
  const fileName = `vectiscan-${domain}-${pkg}-${dateStr}-${timeStr}-v${version}.pdf`;

  // VEC-486: Content-Length MUSS aus dem Objekt kommen, das wir gleich streamen —
  // NICHT aus reports.file_size_bytes. Die DB-Spalte ist eine Momentaufnahme des
  // Erzeugungslaufs und driftet, sobald ein zweiter Lauf denselben MinIO-Key
  // ueberschreibt (report-worker/reporter/worker.py::minio_pdf_path). Bei Drift
  // schnitt Node den Body stumm auf den zu kleinen Wert ab: HTTP 200, kein Log,
  // kein Fehler — der Kunde bekam ein PDF ohne startxref/%%EOF. Fastify laesst
  // ein manuell gesetztes Content-Length bei Stream-Payloads unangetastet
  // (strictContentLength ist per Default false), es gibt also keinen Schutz
  // ausser diesem statObject-Call.
  const stat = await minioClient.statObject(bucket, objectPath);
  const fileSize = stat.size;

  if (recordedSize !== undefined && recordedSize !== null && recordedSize !== fileSize) {
    reply.log?.warn(
      { bucket, objectPath, recordedSize, actualSize: fileSize },
      'report size drift: reports.file_size_bytes disagrees with the stored object — streaming actual size',
    );
  }

  const stream = await minioClient.getObject(bucket, objectPath);

  // Ein kuenftiger Laengen-Mismatch soll laut scheitern statt still zu kuerzen.
  reply.raw.strictContentLength = true;

  return reply
    .header('Content-Type', 'application/pdf')
    .header('Content-Disposition', `attachment; filename="${fileName}"`)
    .header('Content-Length', fileSize)
    .send(stream);
}

// VEC-289: Validierung + Dauer-Labels stammen aus dem kanonischen Katalog.
type ScanPackage = PackageKey;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface CreateOrderBody {
  package?: string;
  targets?: Array<{ raw_input?: unknown; exclusions?: unknown }>;
  // F-P0A-006: Opt-In Shodan-Pre-Warm fuer One-Off-Orders.
  // Default false. Wenn true loest scan-worker beim Scan-Start
  // POST /shodan/scan aus — frischere Shodan-Daten 24-48h spaeter.
  pre_warm_shodan?: boolean;
}

interface OrderParams {
  id: string;
}

interface FindingParams {
  id: string;
  findingId: string;
}

interface ExcludeBody {
  reason?: string;
}

interface OverrideBody {
  field: string;        // 'cvss_score', 'severity', 'title', '_ignored', ...
  value: unknown;       // numeric, string, boolean — landet in JSONB.value
  note?: string;
}

// Whitelist der Felder die ueber das Override-API ueberschrieben werden duerfen.
// Schuetzt vor SQL/JSONB-Injection durch beliebige field-Namen und gegen
// fachliche Schaeden (z.B. ueberschreiben von 'id' oder 'evidence' wuerde
// die Rohdaten korrumpieren).
const ALLOWED_OVERRIDE_FIELDS = new Set([
  'cvss_score',
  'severity',
  'title',
  'description',
  '_ignored',  // markiert Finding als "warnings akzeptiert" ohne Field-Edit
]);

export async function orderRoutes(server: FastifyInstance): Promise<void> {
  // POST /api/orders — requireAuth, multi-target
  // Body: { package, targets: [{raw_input, exclusions?}, ...] }
  server.post<{ Body: CreateOrderBody }>('/api/orders', { preHandler: [requireAuth] }, async (request, reply) => {
    const user = request.user!;
    const body = request.body || {} as CreateOrderBody;
    const pkg = (body.package || 'perimeter').toLowerCase();
    const rawTargets = body.targets || [];

    if (!isPackageKey(pkg)) {
      return reply.status(400).send({
        success: false,
        error: `Invalid package. Must be one of: ${PACKAGE_KEYS.join(', ')}.`,
      });
    }

    const batch = validateTargetBatch(rawTargets);
    if (batch.errors.length > 0 || batch.targets.some(t => !t.valid)) {
      return reply.status(400).send({
        success: false,
        error: 'target_validation_failed',
        data: batch,
      });
    }

    // Resolve customer_id
    let customerId = user.customerId;
    if (!customerId) {
      const customerResult = await query<{ id: string }>(
        'INSERT INTO customers (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email RETURNING id',
        [user.email],
      );
      customerId = customerResult.rows[0].id;
    }

    const validTargets = batch.targets;
    const displayName = validTargets.length === 1
      ? validTargets[0].canonical!
      : `multi-target (${validTargets.length})`;

    // F-P0A-006: opt-in Shodan-Pre-Warm fuer One-Off-Orders.
    const preWarmRequested = body.pre_warm_shodan === true;

    // VEC-436: Zahlungs-Gate fuer kostenpflichtige Einzelscans (mode=payment).
    // D1: Nur Pakete mit one-time-Price im Katalog (heute Perimeter) sind
    // kauf-pflichtig. WebCheck (free) und die sales_assisted-Pakete laufen
    // wie bisher direkt. Hat der Kunde ein aktives Abo fuer dasselbe Paket,
    // ist der Einzelscan bereits abgedeckt → keine zweite Zahlung.
    let mustPay = isOneTimePurchasable(pkg);
    if (mustPay) {
      const activeSub = await query(
        `SELECT 1 FROM subscriptions
          WHERE customer_id = $1 AND package = $2 AND status = 'active' LIMIT 1`,
        [customerId, pkg],
      );
      if (activeSub.rows.length > 0) mustPay = false;
    }

    // Vor dem Anlegen pruefen, ob Stripe + one-time-Preis ueberhaupt
    // konfiguriert sind — sonst saubere 503 statt einer Order, die nie
    // bezahlt werden kann (kein Gratis-Scan als Fallback, VEC-33-Linie).
    let oneTimePriceId: string | null = null;
    if (mustPay) {
      if (!isStripeConfigured()) {
        return reply.status(503).send({
          success: false,
          error: 'payment_not_configured',
          message: 'Zahlungsabwicklung ist derzeit nicht verfuegbar. Bitte spaeter erneut versuchen.',
        });
      }
      oneTimePriceId = getOneTimePriceIdForPackage(pkg);
      if (!oneTimePriceId) {
        return reply.status(503).send({
          success: false,
          error: 'price_not_configured',
          message: `Fuer den Einzelkauf von "${pkg}" ist kein Preis hinterlegt.`,
        });
      }
    }

    // Bezahl-Orders starten 'awaiting_payment' (Scan erst nach Webhook);
    // alle anderen wie bisher 'precheck_running'.
    const initialStatus = mustPay ? 'awaiting_payment' : 'precheck_running';
    const initialPaymentStatus = mustPay ? 'unpaid' : null;

    const orderResult = await query<{ id: string; status: string; package: string; created_at: Date }>(
      `INSERT INTO orders (customer_id, target_url, package, status, target_count, pre_warm_requested, payment_status)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, status, package, created_at`,
      [customerId, displayName, pkg, initialStatus, validTargets.length, preWarmRequested, initialPaymentStatus],
    );
    const order = orderResult.rows[0];

    // Insert scan_targets
    const targetIds: string[] = [];
    const targetStubs: Array<{ id: string; raw_input: string; canonical: string; target_type: string; discovery_policy: string; status: string }> = [];
    for (let i = 0; i < validTargets.length; i++) {
      const t = validTargets[i];
      const exclusions = Array.isArray(rawTargets[i]?.exclusions)
        ? (rawTargets[i].exclusions as unknown[]).filter(e => typeof e === 'string') as string[]
        : [];
      const insertRes = await query<{ id: string }>(
        `INSERT INTO scan_targets
           (order_id, raw_input, canonical, target_type, discovery_policy, exclusions, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending_precheck')
         RETURNING id`,
        [order.id, t.raw_input, t.canonical, t.target_type, t.policy_default, exclusions],
      );
      const tid = insertRes.rows[0].id;
      targetIds.push(tid);
      targetStubs.push({
        id: tid,
        raw_input: t.raw_input,
        canonical: t.canonical!,
        target_type: t.target_type!,
        discovery_policy: t.policy_default!,
        status: 'pending_precheck',
      });
    }

    audit({
      orderId: order.id,
      action: 'order.created',
      details: {
        package: pkg,
        targetCount: validTargets.length,
        targets: targetStubs.map(s => s.canonical),
        preWarmShodan: preWarmRequested,
        requiresPayment: mustPay,
      },
      ip: request.ip,
    });

    // VEC-436: Bezahl-Pfad — KEIN Precheck-Enqueue. Stripe-Checkout-Session
    // (mode=payment) erzeugen; der Scan wird erst nach bestaetigter Zahlung
    // im Webhook (checkout.session.completed) freigeschaltet.
    if (mustPay) {
      let checkoutUrl: string | null = null;
      let checkoutSessionId: string | null = null;
      try {
        const { successUrl, cancelUrl } = getOrderCheckoutUrls(order.id);
        const session = await getStripe().checkout.sessions.create({
          mode: 'payment',
          line_items: [{ price: oneTimePriceId!, quantity: 1 }],
          success_url: successUrl,
          cancel_url: cancelUrl,
          client_reference_id: order.id,
          customer_email: user.email,
          metadata: { order_id: order.id, price_id: oneTimePriceId!, package: pkg },
        });
        checkoutUrl = session.url;
        checkoutSessionId = session.id;
        await query(
          'UPDATE orders SET stripe_checkout_session_id = $1, updated_at = NOW() WHERE id = $2',
          [session.id, order.id],
        );
      } catch (err) {
        request.log.error({ err, orderId: order.id }, 'Stripe one-time checkout session creation failed');
        // Order bleibt 'awaiting_payment' und startet nie ohne Zahlung;
        // der Kunde kann den Kauf neu anstossen.
        return reply.status(502).send({
          success: false,
          error: 'checkout_creation_failed',
          message: 'Checkout konnte nicht gestartet werden. Bitte erneut versuchen.',
        });
      }

      audit({
        orderId: order.id,
        action: 'order.checkout_started',
        details: { package: pkg, priceId: oneTimePriceId, checkoutSessionId },
        ip: request.ip,
      });

      return reply.status(201).send({
        success: true,
        data: {
          id: order.id,
          status: 'awaiting_payment',
          package: order.package,
          targetCount: validTargets.length,
          targets: targetStubs,
          checkoutUrl,
          checkoutSessionId,
          message: 'Order angelegt. Bitte Zahlung via Stripe abschliessen — der Scan startet erst nach bestaetigter Zahlung.',
        },
      });
    }

    // Gratis-/Abo-gedeckter Pfad: Precheck sofort enqueuen.
    await enqueuePrecheck({ orderId: order.id, targetIds });

    return reply.status(201).send({
      success: true,
      data: {
        id: order.id,
        status: 'precheck_running',
        package: order.package,
        targetCount: validTargets.length,
        targets: targetStubs,
      },
    });
  });

  // GET /api/orders — requireAuth, admin sees all, customer sees own
  server.get('/api/orders', { preHandler: [requireAuth] }, async (request) => {
    const user = request.user!;

    let sql: string;
    let params: unknown[];

    const baseSelect = `SELECT o.id, o.target_url, o.package, o.status, o.error_message,
                    o.scan_started_at, o.scan_finished_at, o.created_at,
                    o.hosts_total, o.hosts_completed, o.current_tool, o.current_host,
                    o.subscription_id, o.is_rescan, o.target_count,
                    c.email,
                    EXISTS(SELECT 1 FROM reports r2 WHERE r2.order_id = o.id) AS has_report,
                    (SELECT rr.findings_data->>'overall_risk' FROM reports rr WHERE rr.order_id = o.id ORDER BY rr.created_at DESC LIMIT 1) AS overall_risk,
                    -- VEC-123: autoritative, trigger-berechnete Spalte reports.severity_counts
                    -- statt eingebettetem findings_data->'severity_counts' (Drift-Haertung).
                    (SELECT rr.severity_counts FROM reports rr WHERE rr.order_id = o.id ORDER BY rr.created_at DESC LIMIT 1) AS severity_counts,
                    -- Multi-Target-UX: bis zu 5 Targets pro Order ans Frontend
                    -- liefern, damit das Dashboard die Domains direkt anzeigt
                    -- statt nur "multi-target (N)".
                    (SELECT json_agg(json_build_object('canonical', t.canonical))
                       FROM (SELECT canonical FROM scan_targets
                              WHERE order_id = o.id
                              ORDER BY created_at LIMIT 5) t
                    ) AS targets
             FROM orders o
             JOIN customers c ON o.customer_id = c.id`;

    if (user.role === 'admin') {
      sql = `${baseSelect} ORDER BY o.created_at DESC`;
      params = [];
    } else {
      // VEC-297: KEINE Status-Whitelist mehr — konsistent zu GET /api/orders/:id
      // (VEC-283). Der Customer sieht im Dashboard-Listing ALLE eigenen Orders in
      // jedem Lebenszyklus-Status (precheck_running, pending_target_review,
      // scan_running, report_generating, …), nicht erst wenn der Report fertig ist.
      // Vorher zeigte die Whitelist (report_complete/delivered/report_generating)
      // eine frisch angelegte, laufende Order NICHT in der Liste — ein Erstnutzer
      // sah seine gerade gestartete Order nur via Direkt-URL /scan/[orderId], nicht
      // im Dashboard. o.customer_id = $1 ist die einzige noetige Zugriffsgrenze;
      // Report-Felder (overallRisk/severityCounts) bleiben null solange kein Report.
      sql = `${baseSelect} WHERE o.customer_id = $1 ORDER BY o.created_at DESC`;
      params = [user.customerId];
    }

    const result = await query(sql, params);

    const orders = result.rows.map((row: Record<string, unknown>) => ({
      id: row.id,
      domain: row.target_url,
      email: row.email,
      package: row.package,
      status: row.status,
      // SOLL 9: Fuer Kunden erst nach Freigabe (report_complete/delivered) als
      // downloadbar melden — Admin sieht Reports in jedem Status.
      hasReport: (row.has_report === true || row.has_report === 't')
        && (user.role === 'admin' || row.status === 'report_complete' || row.status === 'delivered'),
      error: row.error_message || null,
      hostsTotal: (row.hosts_total as number) || 0,
      hostsCompleted: (row.hosts_completed as number) || 0,
      currentTool: (row.current_tool as string) || null,
      currentHost: (row.current_host as string) || null,
      startedAt: row.scan_started_at ? (row.scan_started_at as Date).toISOString() : null,
      finishedAt: row.scan_finished_at ? (row.scan_finished_at as Date).toISOString() : null,
      createdAt: (row.created_at as Date).toISOString(),
      overallRisk: (row.overall_risk as string) || null,
      // VEC-123: autoritative lower-case-Spalte → kanonische UPPER-case-Form
      // normalisieren, damit Karten-Antwort byte-gleich zur bisherigen bleibt.
      severityCounts: normalizeSeverityCounts(row.severity_counts),
      businessImpactScore: row.business_impact_score != null ? Number(row.business_impact_score) : null,
      subscriptionId: (row.subscription_id as string) || null,
      isRescan: row.is_rescan === true || row.is_rescan === 't',
      targetCount: row.target_count != null ? Number(row.target_count) : null,
      targets: (row.targets as Array<{ canonical: string }> | null) || null,
    }));

    return { success: true, data: { orders } };
  });

  // POST /api/scans — backwards compat redirect
  server.post('/api/scans', async (_request, reply) => {
    return reply.redirect('/api/orders', 307);
  });

  // GET /api/orders/dashboard-summary — aggregated security cockpit data
  // Optional filters: ?subscriptionId=<uuid> or ?domain=<fqdn>
  server.get('/api/orders/dashboard-summary', { preHandler: [requireAuth] }, async (request) => {
    const user = request.user!;
    const qp = request.query as Record<string, string | undefined>;
    const subscriptionIdFilter = qp.subscriptionId && UUID_REGEX.test(qp.subscriptionId) ? qp.subscriptionId : null;
    const domainFilter = qp.domain ? qp.domain.toLowerCase().slice(0, 255) : null;
    const orderIdFilter = qp.orderId && UUID_REGEX.test(qp.orderId) ? qp.orderId : null;

    // Resolve customer_id
    let customerId = user.customerId;
    if (!customerId && user.role !== 'admin') {
      const custResult = await query<{ id: string }>('SELECT id FROM customers WHERE email = $1', [user.email]);
      if (custResult.rows.length > 0) customerId = custResult.rows[0].id;
    }

    // Build WHERE dynamically — ownership first, then optional scope filters
    // VEC-297: dashboard-summary behaelt BEWUSST den completed-status-Filter.
    // Anders als das Listing (GET /api/orders) ist dies ein Security-Cockpit-
    // Aggregat (Domain-/Scan-/Findings-Zahlen, overallRisk) ueber abgeschlossene
    // Scans. In-progress Orders haben keine Findings; sie aufzunehmen wuerde nur
    // totalScans/domains mit ergebnislosen Eintraegen aufblaehen ("1 Scan, 0
    // Findings" waehrend noch laeuft) — irrefuehrend fuer die Risiko-Karten.
    // Die laufende Order ist via Listing + /scan/[orderId] sichtbar.
    const where: string[] = [`o.status IN ('report_complete', 'delivered', 'pending_review')`];
    const params: unknown[] = [];
    if (user.role !== 'admin') {
      params.push(customerId);
      where.push(`o.customer_id = $${params.length}`);
    }
    if (subscriptionIdFilter) {
      params.push(subscriptionIdFilter);
      where.push(`o.subscription_id = $${params.length}`);
    }
    if (domainFilter) {
      params.push(domainFilter);
      // Only plain single-domain groups (no subscription) — see /scans/dom:<domain>
      where.push(`o.target_url = $${params.length} AND o.subscription_id IS NULL`);
    }
    if (orderIdFilter) {
      params.push(orderIdFilter);
      // Multi-Target-Order ohne Subscription — siehe /scans/ord:<uuid>
      where.push(`o.id = $${params.length}`);
    }

    const result = await query(
      `SELECT o.id, o.target_url AS domain, o.status, o.scan_finished_at,
              r.findings_data->>'overall_risk' AS overall_risk,
              -- VEC-123: autoritative severity_counts-Spalte (Trigger) statt
              -- eingebettetem findings_data->'severity_counts'.
              r.severity_counts AS severity_counts,
              r.findings_data->'findings' AS findings
       FROM orders o
       LEFT JOIN LATERAL (
         SELECT findings_data, severity_counts FROM reports WHERE order_id = o.id ORDER BY created_at DESC LIMIT 1
       ) r ON true
       WHERE ${where.join(' AND ')}
       ORDER BY o.scan_finished_at DESC`,
      params,
    );

    // Aggregate
    const domains = new Set<string>();
    let totalFindings = 0;
    let criticalCount = 0;
    let highCount = 0;
    const topFindings: Array<{ domain: string; title: string; severity: string; cvss: number; orderId: string }> = [];

    for (const row of result.rows as Array<Record<string, unknown>>) {
      domains.add(row.domain as string);
      // VEC-123 AC2: gegen das gelistete findings-Array reconcilen, damit die
      // aggregierten Karten-Zahlen strukturell den Findings entsprechen
      // (kein stiller Drift). Quelle = autoritative Spalte, bei Abweichung
      // gewinnt die frische Zaehlung aus den Findings.
      const sev = reconcileSeverityCounts(row.severity_counts, row.findings, ({ recounted }) => {
        request.log.warn(
          { orderId: row.id, recounted, embedded: row.severity_counts },
          'VEC-123: severity_counts drift in dashboard-summary reconciled to listed findings',
        );
      });
      totalFindings += sev.CRITICAL + sev.HIGH + sev.MEDIUM + sev.LOW;
      criticalCount += sev.CRITICAL;
      highCount += sev.HIGH;
      // Collect top findings from latest scans (max 5)
      const findings = row.findings as Array<Record<string, unknown>> | null;
      if (findings && topFindings.length < 5) {
        for (const f of findings) {
          if (topFindings.length >= 5) break;
          const fsev = ((f.severity as string) || 'INFO').toUpperCase();
          if (['CRITICAL', 'HIGH', 'MEDIUM'].includes(fsev)) {
            topFindings.push({
              domain: row.domain as string,
              title: (f.title as string) || '',
              severity: fsev,
              cvss: parseFloat((f.cvss_score as string) || '0'),
              orderId: row.id as string,
            });
          }
        }
      }
    }

    // Sort top findings by severity then CVSS
    const sevOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
    topFindings.sort((a, b) => (sevOrder[a.severity] ?? 3) - (sevOrder[b.severity] ?? 3) || b.cvss - a.cvss);

    // Overall risk
    let overallRisk = 'LOW';
    if (criticalCount > 0) overallRisk = 'CRITICAL';
    else if (highCount > 0) overallRisk = 'HIGH';
    else if (totalFindings > 0) overallRisk = 'MEDIUM';

    return {
      success: true,
      data: {
        domains: domains.size,
        totalScans: result.rows.length,
        totalFindings,
        criticalCount,
        highCount,
        overallRisk,
        topFindings: topFindings.slice(0, 3),
      },
    };
  });

  // GET /api/orders/:id — requireAuth, ownership check
  server.get<{ Params: OrderParams }>('/api/orders/:id', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // PR-I (Mai 2026): correlation_data NICHT mehr im default-Endpoint
    // (kann mehrere MB pro Order werden — z.B. 1.7MB bei secumetrix.de).
    // Das laesst den Frontend-Page-Load bei grossen Scans 3-4s blockieren.
    // Stattdessen: business_impact_score + correlation_count als Metadaten,
    // Vollinhalt via separatem GET /api/orders/:id/correlation Endpoint.
    const result = await query(
      `SELECT o.id, o.target_url, o.status, o.package, o.customer_id,
              o.discovered_hosts, o.hosts_total, o.hosts_completed,
              o.current_phase, o.current_tool, o.current_host,
              o.scan_started_at, o.scan_finished_at, o.error_message, o.created_at,
              o.subscription_id, o.is_rescan,
              o.passive_intel_summary, o.business_impact_score,
              jsonb_array_length(COALESCE(o.correlation_data, '[]'::jsonb)) AS correlation_count
       FROM orders o WHERE o.id = $1`,
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }

    const order = result.rows[0] as Record<string, unknown>;

    // Ownership check: customer can only see own orders
    if (user.role !== 'admin' && order.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // VEC-283: KEINE Status-Whitelist mehr. Der Owner darf seine eigene Order
    // in JEDEM Lebenszyklus-Status sehen (precheck_running, pending_target_review,
    // scan_running, report_generating, …). Vorher blockierte eine Whitelist
    // (nur report_complete/delivered/report_generating) den frisch registrierten
    // Customer mit "Access denied", sobald er den ersten Scan startete und auf
    // /scan/[orderId] (Status precheck_running) landete — eine Onboarding-Sackgasse.
    // Die Ownership-Pruefung oben ist die einzige noetige Zugriffsgrenze; alle
    // anderen owner-skopierten Endpoints (/results, /findings, /events,
    // /correlation) machen es ebenso. Report-Inhalt bleibt separat gated
    // (overallRisk/severityCounts sind null solange kein Report existiert).

    // Check if report exists + get severity data from latest report.
    // validation_warnings (Migration 028) wird nur fuer Admins ausgeliefert
    // — Customer-Payload bleibt unberuehrt.
    const isAdmin = user.role === 'admin';
    const reportResult = await query(
      `SELECT id, findings_data->>'overall_risk' AS overall_risk,
              -- VEC-123: autoritative Trigger-Spalte statt eingebettetem Feld.
              severity_counts AS severity_counts,
              validation_warnings
       FROM reports WHERE order_id = $1 ORDER BY created_at DESC LIMIT 1`,
      [id],
    );
    // SOLL 9: Report erst nach Admin-Freigabe als vorhanden/downloadbar an Kunden
    // melden (Admin sieht ihn in jedem Status). Der PDF-Download selbst ist zusaetzlich
    // in GET /api/orders/:id/report gegated.
    const orderReleased = order.status === 'report_complete' || order.status === 'delivered';
    const hasReport = reportResult.rows.length > 0 && (isAdmin || orderReleased);
    const latestReport = reportResult.rows[0] as Record<string, unknown> | undefined;

    const orderPackage = (order.package || 'perimeter') as ScanPackage;

    // Read tool output summary from Redis (fast, non-blocking)
    const redisProgress = await getProgressFromRedis(id);
    const toolOutput = redisProgress?.toolOutput as string | undefined;
    const lastCompletedTool = redisProgress?.lastCompletedTool as string | undefined;

    return {
      success: true,
      data: {
        id: order.id,
        domain: order.target_url,
        status: order.status,
        package: orderPackage,
        customerId: order.customer_id,
        estimatedDuration: getPackage(orderPackage)?.durationLong ?? '',
        progress: {
          phase: order.current_phase || null,
          currentTool: order.current_tool || null,
          currentHost: order.current_host || null,
          hostsTotal: order.hosts_total || 0,
          hostsCompleted: order.hosts_completed || 0,
          discoveredHosts: order.discovered_hosts || [],
          toolOutput: toolOutput || null,
          lastCompletedTool: lastCompletedTool || null,
        },
        startedAt: order.scan_started_at ? (order.scan_started_at as Date).toISOString() : null,
        finishedAt: order.scan_finished_at ? (order.scan_finished_at as Date).toISOString() : null,
        error: order.error_message || null,
        hasReport,
        overallRisk: latestReport?.overall_risk || null,
        // VEC-123: lower-case-Spalte → kanonische UPPER-case-Form.
        severityCounts: normalizeSeverityCounts(latestReport?.severity_counts),
        passiveIntelSummary: order.passive_intel_summary || null,
        // PR-I: correlation_data wird separat geladen — hier nur count.
        // Frontend zeigt es per Lazy-Fetch im Admin-Debug-Drawer.
        correlationCount: Number(order.correlation_count || 0),
        businessImpactScore: order.business_impact_score != null ? Number(order.business_impact_score) : null,
        subscriptionId: (order.subscription_id as string) || null,
        isRescan: order.is_rescan === true || order.is_rescan === 't',
        // Validation-Gate-Output (Migration 028) — admin-only.
        // Null wenn kein Report existiert (z.B. STRICT-Block vor Report-Erzeugung).
        validationWarnings: isAdmin ? (latestReport?.validation_warnings ?? null) : undefined,
      },
    };
  });

  // PR-I (Mai 2026): Separater Endpoint fuer das schwere correlation_data
  // JSONB (kann mehrere MB sein). Nur on-demand laden — Default-Page-Load
  // bleibt schnell.
  server.get<{ Params: OrderParams }>(
    '/api/orders/:id/correlation',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }
      const res = await query(
        `SELECT customer_id, correlation_data, business_impact_score, status
         FROM orders WHERE id = $1`,
        [id],
      );
      if (res.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      const o = res.rows[0] as Record<string, unknown>;
      if (user.role !== 'admin' && o.customer_id !== user.customerId) {
        return reply.status(403).send({ success: false, error: 'Access denied' });
      }
      return {
        success: true,
        data: {
          correlationData: o.correlation_data || [],
          businessImpactScore: o.business_impact_score != null ? Number(o.business_impact_score) : null,
        },
      };
    },
  );

  // GET /api/orders/:id/report — auth via JWT or download_token
  server.get<{ Params: OrderParams }>('/api/orders/:id/report', async (request, reply) => {
    const { id } = request.params;
    const queryParams = request.query as Record<string, string>;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Auth strategy 1: download_token from email link (no login needed)
    const downloadToken = queryParams.download_token;
    if (downloadToken) {
      const tokenCheck = await query(
        `SELECT r.id, r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, r.expires_at, r.version, o.target_url, o.package
         FROM reports r JOIN orders o ON r.order_id = o.id
         WHERE r.order_id = $1 AND r.download_token = $2
         LIMIT 1`,
        [id, downloadToken],
      );

      if (tokenCheck.rows.length === 0) {
        return reply.status(403).send({ success: false, error: 'Invalid download token' });
      }

      const report = tokenCheck.rows[0] as Record<string, unknown>;
      // VEC-197: Ablauf fail-CLOSED erzwingen. Ein `expires_at = NULL` (nur noch
      // Legacy-Zeilen vor Migration 034 möglich) darf über den anonymen
      // download_token-Deeplink NICHT „nie ablaufen". Fehlt das Ablaufdatum,
      // gilt die dokumentierte 30-Tage-TTL ab created_at als effektiver Ablauf
      // (identisch zur Backfill-Semantik created_at + 30d). Der JWT-Owner-Pfad
      // bleibt unberührt — Eigentümer können jederzeit eingeloggt herunterladen.
      const expiresAtRaw = report.expires_at as Date | string | null;
      const effectiveExpiry = expiresAtRaw
        ? new Date(expiresAtRaw)
        : new Date(new Date(report.created_at as Date | string).getTime() + REPORT_DOWNLOAD_TTL_MS);
      if (new Date() > effectiveExpiry) {
        return reply.status(410).send({ success: false, error: 'Download link expired' });
      }

      // Increment download count
      await query('UPDATE reports SET download_count = download_count + 1 WHERE id = $1', [report.id]);

      audit({ orderId: id, action: 'report.downloaded', details: { via: 'download_token' }, ip: request.ip });

      return streamReport(reply, report);
    }

    // Auth strategy 2: JWT (Bearer token or ?token= query param)
    const header = request.headers.authorization;
    const jwtToken = header?.startsWith('Bearer ') ? header.slice(7) : queryParams.token;

    if (!jwtToken) {
      return reply.status(401).send({ success: false, error: 'Authentication required' });
    }

    let user;
    try {
      user = verifyJwt(jwtToken);
    } catch {
      return reply.status(401).send({ success: false, error: 'Invalid or expired token' });
    }

    // Ownership check
    const ownerCheck = await query('SELECT customer_id, status FROM orders WHERE id = $1', [id]);
    if (ownerCheck.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    const ownerRow = ownerCheck.rows[0] as Record<string, unknown>;
    if (user.role !== 'admin' && ownerRow.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Freigabe-Gate (SOLL 9): Der Report-DOWNLOAD ist fuer den Kunden erst nach der
    // Admin-Freigabe erlaubt. Der First-Run-Report existiert bereits im Status
    // 'pending_review' (mit noch nicht entfernten False Positives) — ohne dieses Gate
    // koennte der eingeloggte Owner das Vor-Freigabe-PDF via JWT direkt laden. Admin
    // ausgenommen. Der download_token-Pfad oben ist unberuehrt: der Token wird erst nach
    // Freigabe per E-Mail verschickt, sein Besitz belegt bereits die Freigabe.
    if (
      user.role !== 'admin' &&
      ownerRow.status !== 'report_complete' &&
      ownerRow.status !== 'delivered'
    ) {
      return reply.status(403).send({ success: false, error: 'Report not yet released' });
    }

    let result;
    const requestedVersion = (request.query as Record<string, string>).version
      ? parseInt((request.query as Record<string, string>).version, 10)
      : null;

    if (requestedVersion) {
      try {
        result = await query(
          `SELECT r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, r.version, o.target_url, o.package
           FROM reports r JOIN orders o ON r.order_id = o.id
           WHERE r.order_id = $1 AND r.version = $2`,
          [id, requestedVersion],
        );
      } catch {
        // version column doesn't exist yet — fallback
        result = await query(
          `SELECT r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, o.target_url, o.package
           FROM reports r JOIN orders o ON r.order_id = o.id
           WHERE r.order_id = $1 LIMIT 1`,
          [id],
        );
      }
    } else {
      result = await query(
        `SELECT r.minio_bucket, r.minio_path, r.file_size_bytes, r.created_at, r.version, o.target_url, o.package
         FROM reports r JOIN orders o ON r.order_id = o.id
         WHERE r.order_id = $1 ORDER BY r.created_at DESC LIMIT 1`,
        [id],
      );
    }

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Report not yet available' });
    }

    const reportVersion = (result.rows[0] as Record<string, unknown>).version;
    audit({ orderId: id, action: 'report.downloaded', details: { via: 'jwt', userId: user.sub, version: reportVersion }, ip: request.ip });

    return streamReport(reply, result.rows[0] as Record<string, unknown>);
  });

  // GET /api/orders/:id/results — Raw scan results per tool
  server.get<{ Params: OrderParams }>('/api/orders/:id/results', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Verify order exists and check ownership
    const orderResult = await query('SELECT id, status, customer_id FROM orders WHERE id = $1', [id]);
    if (orderResult.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    const order = orderResult.rows[0] as Record<string, unknown>;
    if (user.role !== 'admin' && order.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Fetch all scan_results for this order.
    // A7 (Migration 044): status/skip_reason sind additiv. db.ts kapselt
    // Migration 044 in try/catch ("continuing without it") — schlaegt sie beim
    // Boot fehl, bootet die API OHNE diese Spalten und ein harter SELECT wirft
    // SQLSTATE 42703 (undefined_column) -> 500 bei JEDEM Aufruf. Defensiv: bei
    // 42703 einmalig auf eine Variante OHNE die A7-Spalten zurueckfallen; die
    // camelCase-Mappung unten liefert dann null (wie fuer Legacy-Zeilen).
    let resultsQuery: Awaited<ReturnType<typeof query>>;
    try {
      resultsQuery = await query(RESULTS_SELECT_A7, [id]);
    } catch (err) {
      if ((err as { code?: string }).code === '42703') {
        request.log.warn(
          { orderId: id },
          'scan_results.status/skip_reason fehlt (Migration 044 nicht angewendet) — Fallback ohne A7-Spalten',
        );
        resultsQuery = await query(RESULTS_SELECT_LEGACY, [id]);
      } else {
        throw err;
      }
    }

    const results = resultsQuery.rows.map((row: Record<string, unknown>) => ({
      id: row.id,
      hostIp: row.host_ip || null,
      phase: row.phase,
      toolName: row.tool_name,
      rawOutput: row.raw_output || null,
      exitCode: row.exit_code,
      durationMs: row.duration_ms,
      // A7 (Migration 044): NULL = Legacy-Zeile vor A7, der Consumer leitet
      // den Status dann wie bisher aus exit_code ab.
      status: (row.status as string | null) ?? null,
      skipReason: (row.skip_reason as string | null) ?? null,
      createdAt: (row.created_at as Date).toISOString(),
    }));

    return {
      success: true,
      data: { results },
    };
  });

  // GET /api/orders/:id/screenshot/:safe — Screenshot eines Hosts (PNG-Stream)
  // Hostnamen werden vom scan-worker mit . → _ gemappt + auf 50 chars gekuerzt
  // (siehe redirect_probe.py:_take_screenshot). Wir nehmen den `safe`-String
  // 1:1 und schauen scan-screenshots/<orderId>/<safe>.png. Auth wie /report:
  // Customer sieht eigenes, Admin alles.
  server.get<{ Params: { id: string; safe: string } }>(
    '/api/orders/:id/screenshot/:safe',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, safe } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID' });
      }
      // Path-Traversal verhindern. Format seit PR-D (Mai 2026):
      // `<ip>__<sanitized_fqdn>` mit Punkten in IP und FQDN.
      // Allowed: a-z, 0-9, dot, underscore, hyphen, max 128 Zeichen.
      // Slashes/Backslashes/null werden weiterhin abgelehnt.
      if (!/^[a-z0-9._-]{1,128}$/i.test(safe)) {
        return reply.status(400).send({ success: false, error: 'Invalid screenshot key' });
      }
      const user = request.user!;
      // Ownership-Check
      const ownerCheck = await query(
        'SELECT customer_id FROM orders WHERE id = $1',
        [id],
      );
      if (ownerCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order nicht gefunden.' });
      }
      if (user.role !== 'admin' && user.customerId !== ownerCheck.rows[0].customer_id) {
        return reply.status(403).send({ success: false, error: 'Kein Zugriff.' });
      }
      try {
        const objKey = `${id}/${safe}.png`;
        const stream = await minioClient.getObject('scan-screenshots', objKey);
        reply.header('Content-Type', 'image/png');
        reply.header('Cache-Control', 'private, max-age=3600');
        return reply.send(stream);
      } catch {
        return reply.status(404).send({ success: false, error: 'Screenshot nicht gefunden.' });
      }
    },
  );

  // GET /api/orders/:id/events — LiveView event replay (AI strategy, configs, tool outputs)
  server.get<{ Params: OrderParams }>('/api/orders/:id/events', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Ownership check
    const orderCheck = await query(
      'SELECT customer_id, discovered_hosts, status, error_message FROM orders WHERE id = $1',
      [id],
    );
    if (orderCheck.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    const order = orderCheck.rows[0] as Record<string, unknown>;
    if (user.role !== 'admin' && order.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Fetch AI strategy and configs from scan_results
    const aiResults = await query(
      `SELECT tool_name, host_ip, raw_output, created_at
       FROM scan_results
       WHERE order_id = $1 AND tool_name IN ('ai_host_strategy', 'ai_phase2_config')
       ORDER BY created_at ASC`,
      [id],
    );

    let aiStrategy = null;
    const aiConfigs: Record<string, unknown> = {};

    for (const row of aiResults.rows as Array<Record<string, unknown>>) {
      try {
        const parsed = JSON.parse(row.raw_output as string);
        if (row.tool_name === 'ai_host_strategy') {
          aiStrategy = parsed;
        } else if (row.tool_name === 'ai_phase2_config' && row.host_ip) {
          aiConfigs[row.host_ip as string] = parsed;
        }
      } catch { /* skip unparseable */ }
    }

    // Fetch tool output summaries (non-AI tools, first 150 chars of raw_output)
    const toolResults = await query(
      `SELECT tool_name, host_ip, LEFT(raw_output, 150) as summary, created_at
       FROM scan_results
       WHERE order_id = $1
         AND tool_name NOT IN ('ai_host_strategy', 'ai_phase2_config', 'ai_host_skip')
         AND exit_code >= 0
       ORDER BY created_at ASC`,
      [id],
    );

    const toolOutputs = (toolResults.rows as Array<Record<string, unknown>>).map(row => ({
      tool: row.tool_name,
      host: row.host_ip || '',
      summary: ((row.summary as string) || '').split('\n')[0].slice(0, 100),
      ts: new Date(row.created_at as string).toISOString(),
    }));

    // Load AI debug prompts/responses
    const aiDebugRows = await query(
      `SELECT tool_name, host_ip, raw_output FROM scan_results
       WHERE order_id = $1 AND tool_name LIKE '%_debug' ORDER BY created_at`,
      [id],
    );

    const aiDebug: Record<string, unknown> = {};
    for (const row of aiDebugRows.rows as Array<Record<string, unknown>>) {
      try {
        const data = JSON.parse(row.raw_output as string);
        const key = (row.tool_name as string).replace('_debug', '');
        if (row.host_ip) {
          // Per-host debug (phase2_config)
          if (!aiDebug[key]) aiDebug[key] = {};
          (aiDebug[key] as Record<string, unknown>)[row.host_ip as string] = data;
        } else {
          aiDebug[key] = data;
        }
      } catch { /* skip unparseable */ }
    }

    // Aggregate AI costs for this scan
    let totalCostUsd = 0;
    const costBreakdown: Array<{step: string; model: string; tokens: number; cost_usd: number}> = [];

    // Cost data is in _debug entries and report_cost
    const costRows = await query(
      `SELECT tool_name, raw_output FROM scan_results
       WHERE order_id = $1 AND (tool_name LIKE '%_debug' OR tool_name = 'report_cost')
       ORDER BY created_at`,
      [id],
    );

    for (const row of costRows.rows as Array<Record<string, unknown>>) {
      try {
        const data = JSON.parse(row.raw_output as string);
        // _debug entries have cost nested: {cost: {...}}
        // report_cost entries ARE the cost object directly: {model: ..., total_cost_usd: ...}
        const cost = data.cost || (data.total_cost_usd ? data : null);
        if (cost && typeof cost === 'object' && cost.total_cost_usd) {
          totalCostUsd += cost.total_cost_usd;
          const toolName = row.tool_name as string;
          costBreakdown.push({
            step: toolName === 'report_cost' ? 'report_generation' : toolName.replace('_debug', ''),
            model: cost.model || 'unknown',
            tokens: (cost.input_tokens || 0) + (cost.output_tokens || 0),
            cost_usd: cost.total_cost_usd,
          });
        }
      } catch { /* skip unparseable */ }
    }

    // Load false positive details from phase3 correlation
    const fpRow = await query(
      `SELECT raw_output FROM scan_results
       WHERE order_id = $1 AND tool_name = 'phase3_correlation' LIMIT 1`,
      [id],
    );

    let falsePositives = null;
    if (fpRow.rows.length > 0) {
      try {
        const phase3Data = JSON.parse((fpRow.rows[0] as Record<string, unknown>).raw_output as string);
        falsePositives = {
          count: phase3Data.false_positives_count || 0,
          by_reason: phase3Data.fp_by_reason || {},
          details: phase3Data.fp_details || [],
        };
      } catch { /* skip unparseable */ }
    }

    // Fetch Claude report debug data from MinIO (best-effort, admin only)
    let claudeDebug = null;
    if (user.role === 'admin') {
      try {
        const stream = await minioClient.getObject('scan-debug', `${id}-claude.json`);
        const chunks: Buffer[] = [];
        for await (const chunk of stream) {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        claudeDebug = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
      } catch {
        // File doesn't exist or MinIO unavailable — not critical
      }
    }

    return {
      success: true,
      data: {
        aiStrategy,
        aiConfigs,
        aiDebug,
        toolOutputs,
        discoveredHosts: order.discovered_hosts || [],
        error: order.error_message || null,
        falsePositives,
        claudeDebug,
        costs: totalCostUsd > 0 ? { total_usd: Math.round(totalCostUsd * 10000) / 10000, breakdown: costBreakdown } : null,
      },
    };
  });

  // GET /api/orders/:id/findings — structured findings from report
  server.get<{ Params: OrderParams }>('/api/orders/:id/findings', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Ownership check
    const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
    if (orderCheck.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    if (user.role !== 'admin' && (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    const result = await query(
      `SELECT r.findings_data,
              r.policy_version,
              r.policy_id_distinct,
              r.severity_counts AS audit_severity_counts,
              r.tech_profiles,
              r.additional_findings,
              o.correlation_data,
              o.business_impact_score
         FROM reports r
         JOIN orders o ON o.id = r.order_id
        WHERE r.order_id = $1
        ORDER BY r.created_at DESC
        LIMIT 1`,
      [id],
    );
    if (result.rows.length === 0 || !(result.rows[0] as Record<string, unknown>).findings_data) {
      return reply.status(404).send({ success: false, error: 'Keine Befunddaten verfügbar' });
    }

    // Load excluded findings (table may not exist yet — graceful fallback)
    let excludedIds: string[] = [];
    let exclusionRows: Array<Record<string, unknown>> = [];
    try {
      const exclusions = await query(
        'SELECT finding_id, reason, created_at FROM finding_exclusions WHERE order_id = $1',
        [id],
      );
      excludedIds = exclusions.rows.map((r: Record<string, unknown>) => r.finding_id as string);
      exclusionRows = exclusions.rows as Array<Record<string, unknown>>;
    } catch {
      // finding_exclusions table doesn't exist yet — skip
    }

    const row = result.rows[0] as Record<string, unknown>;
    const findingsData = row.findings_data as Record<string, unknown>;

    // Threat-Intel pro Finding aus correlation_data.enrichment (CVE → {nvd, epss, cisa_kev, exploitdb})
    // mergen — nur wo das Finding eine CVE-ID traegt. Frontend zeigt sonst keinen Badge.
    const correlation = (row.correlation_data ?? null) as Record<string, unknown> | null;
    const enrichment =
      (correlation && (correlation.enrichment as Record<string, unknown> | undefined)) ?? null;
    if (enrichment && Array.isArray(findingsData.findings)) {
      const findingsArr = findingsData.findings as Array<Record<string, unknown>>;
      for (const f of findingsArr) {
        const cve = (f.cve_id as string | undefined) ?? (f.cve as string | undefined);
        if (cve && typeof cve === 'string') {
          // Findings können mehrere CVEs als Komma-Liste tragen — nimm die erste fuer das Badge.
          const firstCve = cve.split(/[,\s]+/).find((c) => /^CVE-\d{4}-\d+$/i.test(c));
          if (firstCve) {
            const intel = enrichment[firstCve.toUpperCase()] ?? enrichment[firstCve];
            if (intel) f.threat_intel = intel;
          }
        }
      }
    }

    return {
      success: true,
      data: {
        ...findingsData,
        // Migration-016-Audit-Felder durchreichen (Q2/2026 Determinismus).
        // VEC-123: audit_severity_counts kommt bereits aus der autoritativen
        // Trigger-Spalte reports.severity_counts (SELECT oben) — diese Detail-
        // seite war nie ein Drift-Standort. Unveraendert gelassen.
        policy_version: row.policy_version ?? null,
        policy_id_distinct: row.policy_id_distinct ?? [],
        audit_severity_counts: row.audit_severity_counts ?? null,
        // Order-Level Business-Impact-Score (aus Phase 3, vor Determinismus-Recompute)
        business_impact_score: row.business_impact_score ?? null,
        // Migration-027 (Mai 2026): Per-Host-Tech-Tabelle + alle Findings inkl. additional
        tech_profiles: row.tech_profiles ?? [],
        additional_findings: row.additional_findings ?? [],
        excluded_finding_ids: excludedIds,
        exclusions: exclusionRows.map((r) => ({
          finding_id: r.finding_id,
          reason: r.reason,
          created_at: r.created_at ? (r.created_at as Date).toISOString() : null,
        })),
      },
    };
  });

  // GET /api/orders/:id/hosts/:host/findings — alle Findings (inkl. additional ueber Top-N-Cap)
  // gefiltert nach affected_hosts oder vhost. Migration 027 (Mai 2026).
  server.get<{ Params: OrderParams & { host: string } }>(
    '/api/orders/:id/hosts/:host/findings',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, host } = request.params;
      const user = request.user!;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }
      const decodedHost = decodeURIComponent(host).trim().toLowerCase();
      if (!decodedHost) {
        return reply.status(400).send({ success: false, error: 'host parameter required' });
      }

      // Ownership-Check
      const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      if (
        user.role !== 'admin' &&
        (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId
      ) {
        return reply.status(403).send({ success: false, error: 'Access denied' });
      }

      const result = await query(
        `SELECT findings_data, additional_findings, tech_profiles
           FROM reports
          WHERE order_id = $1
          ORDER BY created_at DESC
          LIMIT 1`,
        [id],
      );
      if (result.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Keine Befunddaten verfügbar' });
      }
      const row = result.rows[0] as Record<string, unknown>;
      const findingsData = (row.findings_data as Record<string, unknown> | null) ?? {};
      const topNFindings = Array.isArray(findingsData.findings)
        ? (findingsData.findings as Array<Record<string, unknown>>)
        : [];
      const additionalFindings = Array.isArray(row.additional_findings)
        ? (row.additional_findings as Array<Record<string, unknown>>)
        : [];

      // 404 wenn der Host weder in tech_profiles noch in irgendeinem affected_hosts auftaucht.
      const techProfiles = Array.isArray(row.tech_profiles)
        ? (row.tech_profiles as Array<Record<string, unknown>>)
        : [];
      const knownHosts = new Set<string>();
      for (const tp of techProfiles) {
        if (typeof tp.ip === 'string') knownHosts.add(tp.ip.toLowerCase());
        const fqdns = tp.fqdns;
        if (Array.isArray(fqdns)) {
          for (const f of fqdns) {
            if (typeof f === 'string') knownHosts.add(f.toLowerCase());
          }
        }
      }
      const allFindings = [...topNFindings, ...additionalFindings];
      // affected_hosts kann ein String oder Array sein — normalisieren
      const matchHost = (f: Record<string, unknown>): boolean => {
        const affected = f.affected_hosts;
        if (Array.isArray(affected)) {
          if (affected.some((h) => typeof h === 'string' && h.toLowerCase().includes(decodedHost))) {
            return true;
          }
        }
        const vhost = f.vhost;
        if (typeof vhost === 'string' && vhost.toLowerCase() === decodedHost) {
          return true;
        }
        const affectedField = f.affected;
        if (typeof affectedField === 'string' && affectedField.toLowerCase().includes(decodedHost)) {
          return true;
        }
        return false;
      };

      const matched = allFindings.filter(matchHost);
      const matchedTopN = matched.filter((f) => topNFindings.includes(f)).length;

      if (matched.length === 0 && !knownHosts.has(decodedHost)) {
        return reply.status(404).send({
          success: false,
          error: `Host '${decodedHost}' nicht in dieser Order gefunden`,
        });
      }

      return {
        success: true,
        data: {
          host: decodedHost,
          findings: matched,
          total_count: matched.length,
          top_n_count: matchedTopN,
          additional_count: matched.length - matchedTopN,
        },
      };
    },
  );

  // GET /api/orders/:id/diff?compare=<otherId> — compare findings between two scans
  server.get<{ Params: OrderParams }>('/api/orders/:id/diff', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;
    const queryParams = request.query as Record<string, string>;
    const compareId = queryParams.compare;

    if (!UUID_REGEX.test(id) || !compareId || !UUID_REGEX.test(compareId)) {
      return reply.status(400).send({ success: false, error: 'Zwei gültige Order-IDs erforderlich (?compare=<id>)' });
    }

    // Load findings from both orders (latest report each)
    const loadFindings = async (orderId: string) => {
      const res = await query(
        `SELECT r.findings_data->'findings' AS findings, o.target_url, o.scan_finished_at, o.customer_id
         FROM orders o
         LEFT JOIN LATERAL (SELECT findings_data FROM reports WHERE order_id = o.id ORDER BY created_at DESC LIMIT 1) r ON true
         WHERE o.id = $1`,
        [orderId],
      );
      return res.rows[0] as Record<string, unknown> | undefined;
    };

    const [currentData, previousData] = await Promise.all([loadFindings(id), loadFindings(compareId)]);
    if (!currentData || !previousData) {
      return reply.status(404).send({ success: false, error: 'Order nicht gefunden' });
    }

    // Ownership check
    if (user.role !== 'admin' && (currentData.customer_id !== user.customerId || previousData.customer_id !== user.customerId)) {
      return reply.status(403).send({ success: false, error: 'Zugriff verweigert' });
    }

    const currentFindings = (currentData.findings as Array<Record<string, unknown>>) || [];
    const previousFindings = (previousData.findings as Array<Record<string, unknown>>) || [];

    // Build title-based lookup for comparison
    const prevTitles = new Set(previousFindings.map(f => (f.title as string || '').toLowerCase()));
    const currTitles = new Set(currentFindings.map(f => (f.title as string || '').toLowerCase()));

    const newFindings = currentFindings.filter(f => !prevTitles.has((f.title as string || '').toLowerCase()));
    const resolvedFindings = previousFindings.filter(f => !currTitles.has((f.title as string || '').toLowerCase()));
    const unchangedFindings = currentFindings.filter(f => prevTitles.has((f.title as string || '').toLowerCase()));

    return {
      success: true,
      data: {
        current: { orderId: id, domain: currentData.target_url, date: currentData.scan_finished_at, findingsCount: currentFindings.length },
        previous: { orderId: compareId, domain: previousData.target_url, date: previousData.scan_finished_at, findingsCount: previousFindings.length },
        newFindings: newFindings.map(f => ({ title: f.title, severity: f.severity, cvss_score: f.cvss_score })),
        resolvedFindings: resolvedFindings.map(f => ({ title: f.title, severity: f.severity, cvss_score: f.cvss_score })),
        unchangedCount: unchangedFindings.length,
        summary: `${newFindings.length} neue, ${resolvedFindings.length} behobene, ${unchangedFindings.length} unveränderte Befunde`,
      },
    };
  });

  // GET /api/orders/:id/report-versions — list all report versions
  server.get<{ Params: OrderParams }>('/api/orders/:id/report-versions', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    // Ownership check
    const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
    if (orderCheck.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }
    if (user.role !== 'admin' && (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Try query with version column first; fallback if migration 011 hasn't run
    let versions: Array<Record<string, unknown>>;
    try {
      const result = await query(
        `SELECT version, created_at, file_size_bytes, excluded_findings, severity_counts
         FROM reports WHERE order_id = $1
         ORDER BY version DESC`,
        [id],
      );
      versions = result.rows as Array<Record<string, unknown>>;
    } catch {
      // version column doesn't exist yet — fallback
      const result = await query(
        `SELECT created_at, file_size_bytes, severity_counts
         FROM reports WHERE order_id = $1`,
        [id],
      );
      versions = result.rows as Array<Record<string, unknown>>;
    }

    // VEC-123: sumSeverityCounts wird jetzt aus ../lib/severityCounts.js
    // importiert; die autoritative Spalte ist bereits trigger-konsistent.
    return {
      success: true,
      data: {
        versions: versions.map((row, idx) => ({
          version: row.version ?? 1,
          createdAt: row.created_at ? (row.created_at as Date).toISOString() : null,
          findingsCount: sumSeverityCounts(row.severity_counts),
          excludedCount: (row.excluded_findings as string[] || []).length,
          excludedFindings: row.excluded_findings || [],
          fileSizeBytes: row.file_size_bytes || 0,
          isCurrent: idx === 0,
        })),
      },
    };
  });

  // POST /api/orders/:id/findings/:findingId/exclude — exclude a finding
  server.post<{ Params: FindingParams; Body: ExcludeBody }>(
    '/api/orders/:id/findings/:findingId/exclude',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, findingId } = request.params;
      const user = request.user!;
      const { reason } = request.body || {};

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      // Ownership check
      const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      if (user.role !== 'admin' && (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
        return reply.status(403).send({ success: false, error: 'Access denied' });
      }

      await query(
        `INSERT INTO finding_exclusions (order_id, finding_id, excluded_by, reason)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (order_id, finding_id) DO UPDATE SET reason = EXCLUDED.reason`,
        [id, findingId, user.sub, reason || null],
      );

      audit({ orderId: id, action: 'finding.excluded', details: { findingId, reason, userId: user.sub }, ip: request.ip });

      return { success: true, data: null };
    },
  );

  // DELETE /api/orders/:id/findings/:findingId/exclude — unexclude a finding
  server.delete<{ Params: FindingParams }>(
    '/api/orders/:id/findings/:findingId/exclude',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id, findingId } = request.params;
      const user = request.user!;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      // Ownership check
      const orderCheck = await query('SELECT customer_id FROM orders WHERE id = $1', [id]);
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      if (user.role !== 'admin' && (orderCheck.rows[0] as Record<string, unknown>).customer_id !== user.customerId) {
        return reply.status(403).send({ success: false, error: 'Access denied' });
      }

      await query(
        'DELETE FROM finding_exclusions WHERE order_id = $1 AND finding_id = $2',
        [id, findingId],
      );

      audit({ orderId: id, action: 'finding.unexcluded', details: { findingId, userId: user.sub }, ip: request.ip });

      return { success: true, data: null };
    },
  );

  // GET /api/admin/orders/:id/overrides — list all overrides for an order (admin-only)
  // VEC-133: unter /api/admin/* konsolidiert, damit der Edge-Admin-Shield die Route deckt.
  server.get<{ Params: OrderParams }>(
    '/api/admin/orders/:id/overrides',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID' });
      }
      try {
        const result = await query(
          `SELECT id, finding_id, field_name, new_value, note, created_at, created_by
             FROM finding_overrides
            WHERE order_id = $1
            ORDER BY finding_id, field_name`,
          [id],
        );
        return {
          success: true,
          data: {
            overrides: result.rows.map((r: Record<string, unknown>) => ({
              id: r.id,
              findingId: r.finding_id,
              field: r.field_name,
              value: (r.new_value as Record<string, unknown>)?.value ?? null,
              note: r.note,
              createdAt: r.created_at ? (r.created_at as Date).toISOString() : null,
              createdBy: r.created_by,
            })),
          },
        };
      } catch (err) {
        // Tabelle existiert evtl. noch nicht (Migration 029 nicht angewendet)
        const msg = err instanceof Error ? err.message : String(err);
        if (/finding_overrides/.test(msg) && /does not exist/i.test(msg)) {
          return { success: true, data: { overrides: [] } };
        }
        throw err;
      }
    },
  );

  // POST /api/admin/orders/:id/findings/:findingId/override — set/update a field override (admin-only)
  // VEC-133: unter /api/admin/* konsolidiert (Edge-Admin-Shield-Deckung).
  server.post<{ Params: FindingParams; Body: OverrideBody }>(
    '/api/admin/orders/:id/findings/:findingId/override',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id, findingId } = request.params;
      const user = request.user!;
      const { field, value, note } = request.body || ({} as OverrideBody);

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID' });
      }
      if (!field || typeof field !== 'string') {
        return reply.status(400).send({ success: false, error: 'field is required' });
      }
      if (!ALLOWED_OVERRIDE_FIELDS.has(field)) {
        return reply.status(400).send({
          success: false,
          error: `field '${field}' not allowed. Allowed: ${[...ALLOWED_OVERRIDE_FIELDS].join(', ')}`,
        });
      }
      // value-Validierung pro Feld — defensive, damit das PDF nicht crashes
      if (field === 'cvss_score') {
        const n = typeof value === 'number' ? value : Number(value);
        if (!Number.isFinite(n) || n < 0 || n > 10) {
          return reply.status(400).send({ success: false, error: 'cvss_score must be 0..10' });
        }
      } else if (field === 'severity') {
        const ALLOWED_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
        if (typeof value !== 'string' || !ALLOWED_SEVERITIES.includes(value.toUpperCase())) {
          return reply.status(400).send({
            success: false,
            error: `severity must be one of ${ALLOWED_SEVERITIES.join('/')}`,
          });
        }
      } else if (field === '_ignored') {
        if (typeof value !== 'boolean') {
          return reply.status(400).send({ success: false, error: '_ignored must be boolean' });
        }
      } else if (field === 'title' || field === 'description') {
        if (typeof value !== 'string' || value.length === 0 || value.length > 2000) {
          return reply.status(400).send({ success: false, error: `${field} must be 1..2000 chars` });
        }
      }

      const orderCheck = await query('SELECT id FROM orders WHERE id = $1', [id]);
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }

      try {
        const ins = await query(
          `INSERT INTO finding_overrides (order_id, finding_id, field_name, new_value, note, created_by)
           VALUES ($1, $2, $3, $4::jsonb, $5, $6)
           ON CONFLICT (order_id, finding_id, field_name)
           DO UPDATE SET new_value = EXCLUDED.new_value, note = EXCLUDED.note,
                         created_at = now(), created_by = EXCLUDED.created_by
           RETURNING id, created_at`,
          [id, findingId, field, JSON.stringify({ value }), note || null, user.sub],
        );
        audit({
          orderId: id,
          action: 'finding.overridden',
          details: { findingId, field, value, note, userId: user.sub },
          ip: request.ip,
        });
        const row = ins.rows[0] as Record<string, unknown>;
        return {
          success: true,
          data: {
            id: row.id,
            findingId,
            field,
            value,
            note: note || null,
            createdAt: row.created_at ? (row.created_at as Date).toISOString() : null,
          },
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (/finding_overrides/.test(msg) && /does not exist/i.test(msg)) {
          return reply.status(503).send({
            success: false,
            error: 'finding_overrides Tabelle fehlt — Migration 029 ausstehend',
          });
        }
        throw err;
      }
    },
  );

  // DELETE /api/admin/orders/:id/findings/:findingId/override?field=cvss_score — remove an override (admin-only)
  // VEC-133: unter /api/admin/* konsolidiert (Edge-Admin-Shield-Deckung).
  server.delete<{ Params: FindingParams; Querystring: { field?: string } }>(
    '/api/admin/orders/:id/findings/:findingId/override',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id, findingId } = request.params;
      const user = request.user!;
      const field = request.query.field;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID' });
      }
      if (!field) {
        return reply.status(400).send({ success: false, error: 'field query param required' });
      }

      const r = await query(
        `DELETE FROM finding_overrides
          WHERE order_id = $1 AND finding_id = $2 AND field_name = $3`,
        [id, findingId, field],
      );
      audit({
        orderId: id,
        action: 'finding.override_removed',
        details: { findingId, field, userId: user.sub },
        ip: request.ip,
      });
      return { success: true, data: { deleted: r.rowCount ?? 0 } };
    },
  );

  // POST /api/orders/:id/regenerate-report — regenerate report with excluded findings
  server.post<{ Params: OrderParams }>(
    '/api/orders/:id/regenerate-report',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      // Ownership check + get order details
      const orderCheck = await query(
        'SELECT customer_id, target_url, package, status FROM orders WHERE id = $1',
        [id],
      );
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      const order = orderCheck.rows[0] as Record<string, unknown>;
      if (user.role !== 'admin' && order.customer_id !== user.customerId) {
        return reply.status(403).send({ success: false, error: 'Access denied' });
      }

      // Allow regeneration for completed orders and failed reports (scan data still exists)
      // 'scan_complete' deckt den Fall ab dass der Report-Worker den Job nie abgearbeitet
      // hat (z.B. Container down zum Zeitpunkt des Enqueue) — Daten liegen in MinIO,
      // re-enqueue ist sicher.
      const status = order.status as string;
      const allowedStatuses = [
        'report_complete', 'completed', 'failed', 'report_generating',
        'cancelled', 'scan_complete', 'delivered', 'pending_review',
      ];
      if (!allowedStatuses.includes(status)) {
        return reply.status(409).send({
          success: false,
          error: `Report kann nur bei abgeschlossenen oder fehlgeschlagenen Orders neu generiert werden (aktuell: ${status})`,
        });
      }

      // Load excluded findings
      const exclusions = await query(
        'SELECT finding_id, reason FROM finding_exclusions WHERE order_id = $1',
        [id],
      );
      const excludedFindings = exclusions.rows.map((r: Record<string, unknown>) => ({
        finding_id: r.finding_id,
        reason: r.reason,
      }));

      // Update order status
      await query(
        "UPDATE orders SET status = 'report_generating', updated_at = NOW() WHERE id = $1",
        [id],
      );

      // Enqueue report job with excluded findings
      await reportQueue.add('report', {
        orderId: id,
        rawDataPath: `${id}.tar.gz`,
        package: order.package as string,
        excludedFindings,
        regenerate: true,
      });

      audit({
        orderId: id,
        action: 'report.regenerate',
        details: { userId: user.sub, excludedCount: excludedFindings.length },
        ip: request.ip,
      });

      // Notify WebSocket clients
      await publishEvent(id, {
        type: 'status',
        orderId: id,
        status: 'report_generating',
      });

      return {
        success: true,
        data: { message: 'Report wird neu generiert' },
      };
    },
  );

  // ── Admin Review Workflow ──────────────────────────────────

  // GET /api/admin/pending-reviews — list all orders pending admin review
  server.get('/api/admin/pending-reviews', { preHandler: [requireAuth, requireAdmin] }, async () => {
    const result = await query(
      `SELECT o.id, o.target_url AS domain, o.package, o.status, o.created_at, o.scan_finished_at,
              o.correlation_data, o.business_impact_score,
              c.email AS customer_email,
              -- VEC-123: nur die autoritative Trigger-Spalte laden (findings_data
              -- wurde hier nur fuer das eingebettete severity_counts gebraucht).
              r.severity_counts
       FROM orders o
       LEFT JOIN customers c ON c.id = o.customer_id
       LEFT JOIN reports r ON r.order_id = o.id AND r.superseded_by IS NULL
       WHERE o.status = 'pending_review'
       ORDER BY o.scan_finished_at ASC`,
    );

    const reviews = result.rows.map((row: Record<string, unknown>) => {
      return {
        id: row.id,
        domain: row.domain,
        package: row.package,
        status: row.status,
        customerEmail: row.customer_email,
        createdAt: row.created_at,
        scanFinishedAt: row.scan_finished_at,
        businessImpactScore: row.business_impact_score,
        // VEC-123: autoritative Trigger-Spalte → kanonische UPPER-case-Form.
        severityCounts: normalizeSeverityCounts(row.severity_counts),
      };
    });

    return { success: true, data: { reviews } };
  });

  // POST /api/admin/orders/:id/approve — approve a pending review, trigger report generation
  server.post<{ Params: OrderParams }>(
    '/api/admin/orders/:id/approve',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      const orderCheck = await query(
        'SELECT status, target_url, package, customer_id FROM orders WHERE id = $1',
        [id],
      );
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }

      const order = orderCheck.rows[0] as Record<string, unknown>;
      if (order.status !== 'pending_review') {
        return reply.status(409).send({
          success: false,
          error: `Order ist nicht im Review-Status (aktuell: ${order.status})`,
        });
      }

      // Load excluded findings (admin may have marked FPs before approving)
      const exclusions = await query(
        'SELECT finding_id, reason FROM finding_exclusions WHERE order_id = $1',
        [id],
      );
      const excludedFindings = exclusions.rows.map((r: Record<string, unknown>) => ({
        finding_id: r.finding_id,
        reason: r.reason,
      }));

      // Mark as approved
      await query(
        `UPDATE orders SET status = 'approved', reviewed_by = $1, reviewed_at = NOW(),
         updated_at = NOW() WHERE id = $2`,
        [user.sub, id],
      );

      // Enqueue report generation (approved flag tells worker to set report_complete)
      await reportQueue.add('report', {
        orderId: id,
        rawDataPath: `${id}.tar.gz`,
        package: order.package as string,
        excludedFindings,
        approved: true,
      });

      // Update status to report_generating
      await query(
        "UPDATE orders SET status = 'report_generating', updated_at = NOW() WHERE id = $1",
        [id],
      );

      await publishEvent(id, { type: 'status', orderId: id, status: 'report_generating' });

      audit({
        orderId: id,
        action: 'order.approved',
        details: { userId: user.sub, excludedCount: excludedFindings.length },
        ip: request.ip,
      });

      return { success: true, data: { message: 'Review genehmigt, Report wird generiert.' } };
    },
  );

  // POST /api/admin/orders/:id/reject — reject a pending review
  server.post<{ Params: OrderParams }>(
    '/api/admin/orders/:id/reject',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      const user = request.user!;
      const body = request.body as Record<string, unknown> | null;
      const reason = (body?.reason as string) || '';

      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
      }

      const orderCheck = await query('SELECT status FROM orders WHERE id = $1', [id]);
      if (orderCheck.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }

      const order = orderCheck.rows[0] as Record<string, unknown>;
      if (order.status !== 'pending_review') {
        return reply.status(409).send({
          success: false,
          error: `Order ist nicht im Review-Status (aktuell: ${order.status})`,
        });
      }

      await query(
        `UPDATE orders SET status = 'rejected', reviewed_by = $1, reviewed_at = NOW(),
         review_notes = $2, updated_at = NOW() WHERE id = $3`,
        [user.sub, reason, id],
      );

      await publishEvent(id, { type: 'status', orderId: id, status: 'rejected' });

      audit({
        orderId: id,
        action: 'order.rejected',
        details: { userId: user.sub, reason },
        ip: request.ip,
      });

      return { success: true, data: { message: 'Review abgelehnt.' } };
    },
  );

  // DELETE /api/orders/:id — soft cancel or admin hard delete
  server.delete<{ Params: OrderParams }>('/api/orders/:id', { preHandler: [requireAuth] }, async (request, reply) => {
    const { id } = request.params;
    const user = request.user!;
    const queryParams = request.query as Record<string, string>;
    const permanent = queryParams.permanent === 'true';

    if (!UUID_REGEX.test(id)) {
      return reply.status(400).send({ success: false, error: 'Invalid order ID format' });
    }

    const result = await query(
      'SELECT id, status, customer_id FROM orders WHERE id = $1',
      [id],
    );

    if (result.rows.length === 0) {
      return reply.status(404).send({ success: false, error: 'Order not found' });
    }

    const order = result.rows[0] as Record<string, unknown>;

    // Ownership check
    if (user.role !== 'admin' && order.customer_id !== user.customerId) {
      return reply.status(403).send({ success: false, error: 'Access denied' });
    }

    // Admin hard delete: ?permanent=true
    if (permanent) {
      if (user.role !== 'admin') {
        return reply.status(403).send({ success: false, error: 'Only admins can permanently delete orders' });
      }

      // Clean up MinIO objects (best-effort, don't block on errors)
      try {
        await minioClient.removeObject('scan-rawdata', `${id}.tar.gz`);
      } catch { /* ignore — file may not exist */ }
      try {
        await minioClient.removeObject('scan-reports', `${id}.pdf`);
      } catch { /* ignore — file may not exist */ }

      // Delete audit_log entries (no CASCADE on this FK)
      await query('DELETE FROM audit_log WHERE order_id = $1', [id]);

      // Delete order (CASCADE removes scan_results + reports)
      await query('DELETE FROM orders WHERE id = $1', [id]);

      // orderId: null because the order + its audit_log entries were just deleted (FK constraint)
      audit({ orderId: null, action: 'order.deleted', details: { deletedOrderId: id, admin: user.email, domain: order.target_url }, ip: request.ip });

      return { success: true, data: null };
    }

    // Soft cancel: only for running orders
    const status = order.status as string;
    const cancellableStatuses = ['verification_pending', 'verified', 'created', 'queued', 'scanning', 'dns_recon', 'scan_phase1', 'scan_phase2', 'scan_complete', 'report_generating'];
    if (!cancellableStatuses.includes(status)) {
      return reply.status(409).send({
        success: false,
        error: `Order cannot be cancelled in status: ${status}`,
      });
    }

    await query(
      "UPDATE orders SET status = 'cancelled', error_message = 'Vom Benutzer abgebrochen', scan_finished_at = NOW(), updated_at = NOW() WHERE id = $1",
      [id],
    );

    audit({ orderId: id, action: 'order.cancelled', details: { userId: user.sub, previousStatus: status }, ip: request.ip });

    // Notify via Redis Pub/Sub so WebSocket clients get the update
    await publishEvent(id, {
      type: 'status',
      orderId: id,
      status: 'cancelled',
      error: 'Vom Benutzer abgebrochen',
    });

    return { success: true, data: null };
  });

  // --- Admin: Re-queue report generation ---
  // VEC-133: unter /api/admin/* konsolidiert (Edge-Admin-Shield-Deckung).
  server.post<{ Params: OrderParams }>(
    '/api/admin/orders/:id/requeue-report',
    { preHandler: [requireAuth, requireAdmin] },
    async (request, reply) => {
      const { id } = request.params;
      if (!UUID_REGEX.test(id)) {
        return reply.status(400).send({ success: false, error: 'Invalid order ID' });
      }

      // Fetch order
      const orderResult = await query(
        'SELECT id, target_url, package, status FROM orders WHERE id = $1',
        [id],
      );
      if (orderResult.rows.length === 0) {
        return reply.status(404).send({ success: false, error: 'Order not found' });
      }
      const order = orderResult.rows[0] as Record<string, unknown>;
      const domain = order.target_url as string;

      // Fetch host inventory from scan_results (ai_host_strategy stores it)
      const invResult = await query(
        `SELECT raw_output FROM scan_results
         WHERE order_id = $1 AND tool_name = 'ai_host_strategy' LIMIT 1`,
        [id],
      );
      let hostInventory: Record<string, unknown> = { hosts: [], domain };
      if (invResult.rows.length > 0) {
        try {
          const parsed = JSON.parse((invResult.rows[0] as Record<string, unknown>).raw_output as string);
          if (parsed.hosts) hostInventory = parsed;
        } catch { /* use default */ }
      }

      // Fetch tech profiles from scan_results
      const techResult = await query(
        `SELECT raw_output FROM scan_results
         WHERE order_id = $1 AND tool_name = 'ai_tech_analysis_debug' LIMIT 1`,
        [id],
      );
      let techProfiles: unknown[] = [];
      if (techResult.rows.length > 0) {
        try {
          techProfiles = JSON.parse((techResult.rows[0] as Record<string, unknown>).raw_output as string);
        } catch { /* use default */ }
      }

      // Fetch phase3 correlation data
      const p3Result = await query(
        `SELECT raw_output FROM scan_results
         WHERE order_id = $1 AND tool_name = 'phase3_correlation' LIMIT 1`,
        [id],
      );
      let phase3Data: Record<string, unknown> | null = null;
      if (p3Result.rows.length > 0) {
        try {
          phase3Data = JSON.parse((p3Result.rows[0] as Record<string, unknown>).raw_output as string);
        } catch { /* skip */ }
      }

      // Reset status to scan_complete so the report worker picks it up
      await query(
        `UPDATE orders SET status = 'scan_complete', error_message = NULL WHERE id = $1`,
        [id],
      );

      // Build and enqueue report job
      const jobPayload: Record<string, unknown> = {
        orderId: id,
        rawDataPath: `${id}.tar.gz`,
        hostInventory,
        techProfiles,
        package: order.package || 'perimeter',
      };

      // BEFUND 4: Eine phase3_correlation-skip-Zeile traegt raw_output="{}",
      // JSON.parse("{}") ergibt ein leeres, aber truthy Objekt. Ohne den
      // Keys-Check wuerde der jobPayload dann enrichment={}/
      // correlatedFindings=[]/businessImpactScore=0/phase3Summary={} setzen
      // statt die Felder ungesetzt zu lassen (Vorverhalten bei null). Ein leeres
      // phase3-Objekt muss wie "nicht vorhanden" behandelt werden.
      if (phase3Data && Object.keys(phase3Data).length > 0) {
        jobPayload.enrichment = phase3Data.enrichment || {};
        jobPayload.correlatedFindings = phase3Data.correlated_findings || [];
        jobPayload.businessImpactScore = phase3Data.business_impact_score || 0.0;
        jobPayload.phase3Summary = phase3Data.phase3_summary || {};
      }

      await reportQueue.add('report', jobPayload);

      await audit({ orderId: id, action: 'report.regenerate', ip: request.ip });
      server.log.info({ orderId: id }, 'Report job re-queued by admin');

      return { success: true, data: { message: 'Report job re-queued', orderId: id } };
    },
  );

  // POST /api/orders/validate-targets — pro Zeile eine TargetValidation zurueck
  server.post<{ Body: { targets?: Array<{ raw_input?: unknown; exclusions?: unknown }> } }>(
    '/api/orders/validate-targets',
    { preHandler: [requireAuth] },
    async (request, reply) => {
      const body = request.body || {};
      const result = validateTargetBatch(body.targets || []);
      return reply.send({ success: true, data: result });
    },
  );

  // Backwards-compat redirects for old scan endpoints
  server.get<{ Params: OrderParams }>('/api/scans/:id', async (request, reply) => {
    return reply.redirect(`/api/orders/${request.params.id}`, 301);
  });

  server.get<{ Params: OrderParams }>('/api/scans/:id/report', async (request, reply) => {
    return reply.redirect(`/api/orders/${request.params.id}/report`, 301);
  });

  server.delete<{ Params: OrderParams }>('/api/scans/:id', async (request, reply) => {
    return reply.redirect(`/api/orders/${request.params.id}`, 307);
  });

  // GET /api/admin/cost-overview?period=30d — Token-/Cost-Cockpit (Admin)
  // M6 (PR-KI-Optim, 2026-05-03)
  server.get<{ Querystring: { period?: string } }>(
    '/api/admin/cost-overview',
    { preHandler: [requireAuth, requireAdmin] },
    async (request) => {
      const period = (request.query.period || '30d').toLowerCase();
      const days = period === '7d' ? 7 : period === '90d' ? 90 : 30;
      const totals = await query<{
        total_calls: string; total_cost_usd: string;
        total_input_tokens: string; total_output_tokens: string;
        total_cache_read_tokens: string; total_cache_creation_tokens: string;
        cache_hits: string;
      }>(
        `SELECT COUNT(*) AS total_calls,
                COALESCE(SUM(total_cost_usd), 0) AS total_cost_usd,
                COALESCE(SUM(input_tokens), 0) AS total_input_tokens,
                COALESCE(SUM(output_tokens), 0) AS total_output_tokens,
                COALESCE(SUM(cache_read_tokens), 0) AS total_cache_read_tokens,
                COALESCE(SUM(cache_creation_tokens), 0) AS total_cache_creation_tokens,
                COALESCE(SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END), 0) AS cache_hits
           FROM ai_call_costs
          WHERE created_at >= NOW() - ($1 || ' days')::interval`,
        [String(days)],
      );
      const byStep = await query(
        `SELECT ki_step, model,
                COUNT(*) AS calls,
                COALESCE(SUM(total_cost_usd), 0) AS cost_usd,
                COALESCE(SUM(input_tokens), 0) AS input_tokens,
                COALESCE(SUM(output_tokens), 0) AS output_tokens,
                COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens
           FROM ai_call_costs
          WHERE created_at >= NOW() - ($1 || ' days')::interval
          GROUP BY ki_step, model
          ORDER BY cost_usd DESC`,
        [String(days)],
      );
      const topOrders = await query(
        `SELECT order_id,
                COUNT(*) AS calls,
                COALESCE(SUM(total_cost_usd), 0) AS cost_usd
           FROM ai_call_costs
          WHERE created_at >= NOW() - ($1 || ' days')::interval AND order_id IS NOT NULL
          GROUP BY order_id
          ORDER BY cost_usd DESC
          LIMIT 20`,
        [String(days)],
      );
      const t = totals.rows[0];
      return {
        success: true,
        data: {
          period: `${days}d`,
          totals: {
            totalCalls: Number(t.total_calls),
            totalCostUsd: Number(t.total_cost_usd),
            totalInputTokens: Number(t.total_input_tokens),
            totalOutputTokens: Number(t.total_output_tokens),
            totalCacheReadTokens: Number(t.total_cache_read_tokens),
            totalCacheCreationTokens: Number(t.total_cache_creation_tokens),
            cacheHits: Number(t.cache_hits),
            cacheHitRate: Number(t.total_calls) > 0
              ? Number(t.cache_hits) / Number(t.total_calls)
              : 0,
          },
          byStep: byStep.rows.map((r: Record<string, unknown>) => ({
            kiStep: r.ki_step,
            model: r.model,
            calls: Number(r.calls),
            costUsd: Number(r.cost_usd),
            inputTokens: Number(r.input_tokens),
            outputTokens: Number(r.output_tokens),
            cacheReadTokens: Number(r.cache_read_tokens),
          })),
          topOrders: topOrders.rows.map((r: Record<string, unknown>) => ({
            orderId: r.order_id,
            calls: Number(r.calls),
            costUsd: Number(r.cost_usd),
          })),
        },
      };
    },
  );
}
