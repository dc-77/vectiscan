/**
 * Demo-Seed für VectiScan (VEC-86 / PA-6).
 *
 * Legt einen synthetischen Demo-Mandanten mit reproduzierbarem Login und je
 * einem fertigen Report pro umsatzrelevantem Paket (WebCheck, Perimeter,
 * Compliance) an. Alle Zieldaten sind synthetisch (RFC-6761-`.test`-TLD,
 * keine echten Kundendaten/PII). Erfüllt AC1 + AC2 aus VEC-86.
 *
 * Eigenschaften:
 *  - Idempotent: räumt vorhandene Demo-Daten (feste UUIDs) auf und legt sie neu an.
 *  - Deterministisch: feste IDs, feste Download-Tokens, feste Datumswerte.
 *  - Self-contained: erzeugt echte, herunterladbare PDFs (siehe demoReportPdf.ts),
 *    lädt sie nach MinIO und füllt reports.findings_data für Dashboard/Risk-Gauge.
 *
 * Aufruf:   npm run seed:demo            (im api-Container / lokal mit DB+MinIO)
 * ENV:      DEMO_PASSWORD (Default: VectiScanDemo2026!)
 *           DATABASE_URL, MINIO_* (wie API)
 */
import fs from 'fs';
import path from 'path';
import { pool, query } from '../lib/db.js';
import { hashPassword } from '../lib/auth.js';
import { minioClient } from '../lib/minio.js';
import { generateDemoReportPdf, DemoFindingsData } from './demoReportPdf.js';

// ── Feste IDs (Idempotenz) ───────────────────────────────────────────────────
const DEMO_CUSTOMER_ID = 'd0000000-0000-4000-a000-000000000001';
const DEMO_USER_ID = 'd0000000-0000-4000-a000-000000000002';
const DEMO_EMAIL = 'demo@vectiscan.tech';
const REPORTS_BUCKET = 'scan-reports';

interface PkgSpec {
  pkg: 'webcheck' | 'perimeter' | 'compliance';
  orderId: string;
  reportId: string;
  targetId: string;
  downloadToken: string;
  /** "Scan"-Zeitpunkt — deterministisch, gestaffelt. */
  scannedAt: string;
}

const SPECS: PkgSpec[] = [
  {
    pkg: 'webcheck',
    orderId: 'd0000000-0000-4000-a000-000000000101',
    reportId: 'd0000000-0000-4000-a000-000000000201',
    targetId: 'd0000000-0000-4000-a000-000000000301',
    downloadToken: 'demo-token-webcheck-0001',
    scannedAt: '2026-05-18T09:20:00Z',
  },
  {
    pkg: 'perimeter',
    orderId: 'd0000000-0000-4000-a000-000000000102',
    reportId: 'd0000000-0000-4000-a000-000000000202',
    targetId: 'd0000000-0000-4000-a000-000000000302',
    downloadToken: 'demo-token-perimeter-0001',
    scannedAt: '2026-05-21T14:05:00Z',
  },
  {
    pkg: 'compliance',
    orderId: 'd0000000-0000-4000-a000-000000000103',
    reportId: 'd0000000-0000-4000-a000-000000000203',
    targetId: 'd0000000-0000-4000-a000-000000000303',
    downloadToken: 'demo-token-compliance-0001',
    scannedAt: '2026-05-26T11:40:00Z',
  },
];

interface Fixture extends DemoFindingsData {
  target: string;
  company_name: string;
}

function loadFixture(pkg: string): Fixture {
  const file = path.join(__dirname, 'demo-data', `${pkg}.json`);
  return JSON.parse(fs.readFileSync(file, 'utf-8')) as Fixture;
}

/** Strippt Hilfsfelder → exakt das findings_data-Objekt, das auch der Report-Worker speichert. */
function toFindingsData(fx: Fixture): Record<string, unknown> {
  const { target: _t, company_name: _c, ...rest } = fx;
  return rest;
}

async function ensureBucket(): Promise<void> {
  const exists = await minioClient.bucketExists(REPORTS_BUCKET);
  if (!exists) await minioClient.makeBucket(REPORTS_BUCKET);
}

async function cleanup(): Promise<void> {
  const orderIds = SPECS.map((s) => s.orderId);
  // audit_log hat keinen CASCADE auf orders → zuerst entfernen.
  await query('DELETE FROM audit_log WHERE order_id = ANY($1::uuid[])', [orderIds]);
  // orders-CASCADE räumt reports, scan_targets, scan_results, finding_exclusions.
  await query('DELETE FROM orders WHERE customer_id = $1', [DEMO_CUSTOMER_ID]);
  await query('DELETE FROM users WHERE customer_id = $1', [DEMO_CUSTOMER_ID]);
  await query('DELETE FROM customers WHERE id = $1', [DEMO_CUSTOMER_ID]);
}

async function seed(): Promise<void> {
  const password = process.env.DEMO_PASSWORD || 'VectiScanDemo2026!';
  const pwHash = await hashPassword(password);

  await ensureBucket();
  await cleanup();

  // 1) Mandant + Login
  await query(
    `INSERT INTO customers (id, email, company_name, created_at)
     VALUES ($1, $2, $3, NOW())`,
    [DEMO_CUSTOMER_ID, DEMO_EMAIL, 'VectiScan Demo GmbH'],
  );
  await query(
    `INSERT INTO users (id, email, password_hash, role, customer_id, created_at, updated_at)
     VALUES ($1, $2, $3, 'customer', $4, NOW(), NOW())`,
    [DEMO_USER_ID, DEMO_EMAIL, pwHash, DEMO_CUSTOMER_ID],
  );

  // 2) Pro Paket: Order + Target + PDF + Report
  for (const spec of SPECS) {
    const fx = loadFixture(spec.pkg);
    const findingsData = toFindingsData(fx);
    const finishedAt = spec.scannedAt;
    const startedAt = new Date(new Date(spec.scannedAt).getTime() - 30 * 60 * 1000).toISOString();
    const totalFindings = fx.findings.length;

    // Order — fertig & bezahlt
    await query(
      `INSERT INTO orders (
         id, customer_id, target_url, package, status,
         verification_method, verified_at,
         paid_at, amount_cents, currency,
         scan_started_at, scan_finished_at,
         hosts_total, hosts_completed, target_count,
         created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4, 'report_complete',
         'manual', $5,
         $5, $6, 'EUR',
         $7, $5,
         $8, $8, 1,
         $5, $5
       )`,
      [
        spec.orderId,
        DEMO_CUSTOMER_ID,
        fx.target,
        spec.pkg,
        finishedAt,
        packagePriceCents(spec.pkg),
        startedAt,
        spec.pkg === 'webcheck' ? 1 : 3,
      ],
    );

    // Scan-Target (für Multi-Target-UX im Dashboard)
    await query(
      `INSERT INTO scan_targets (
         id, order_id, raw_input, canonical, target_type, discovery_policy,
         status, approved_by, approved_at, created_at, updated_at
       ) VALUES ($1, $2, $3, $3, 'fqdn_root', 'enumerate', 'approved', NULL, $4, $4, $4)`,
      [spec.targetId, spec.orderId, fx.target, finishedAt],
    );

    // PDF erzeugen + nach MinIO laden
    const pdf = generateDemoReportPdf(fx, fx.target, finishedAt);
    const objectPath = `demo/${spec.pkg}/VectiScan-Demo-${spec.pkg}.pdf`;
    await minioClient.putObject(REPORTS_BUCKET, objectPath, pdf, pdf.length, {
      'Content-Type': 'application/pdf',
    });

    // Report-Datensatz (severity_counts-Spalte wird per Trigger aus findings_data abgeleitet)
    await query(
      `INSERT INTO reports (
         id, order_id, minio_bucket, minio_path, file_size_bytes,
         download_token, download_count, expires_at, findings_data, version, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, 1, $9)`,
      [
        spec.reportId,
        spec.orderId,
        REPORTS_BUCKET,
        objectPath,
        pdf.length,
        spec.downloadToken,
        new Date(new Date(finishedAt).getTime() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        JSON.stringify(findingsData),
        finishedAt,
      ],
    );

    // Audit-Spur
    await query(
      `INSERT INTO audit_log (order_id, action, details, created_at)
       VALUES ($1, 'report.demo_seeded', $2, $3)`,
      [spec.orderId, JSON.stringify({ package: spec.pkg, findings: totalFindings, synthetic: true }), finishedAt],
    );

    console.log(
      `  ✓ ${spec.pkg.padEnd(10)} ${fx.target.padEnd(42)} ${fx.overall_risk.padEnd(8)} ` +
        `${totalFindings} Befunde · PDF ${(pdf.length / 1024).toFixed(1)} KB`,
    );
  }
}

function packagePriceCents(pkg: string): number {
  switch (pkg) {
    case 'webcheck':
      return 19900;
    case 'perimeter':
      return 89900;
    case 'compliance':
      return 149900;
    default:
      return 0;
  }
}

async function main(): Promise<void> {
  console.log('VectiScan Demo-Seed (VEC-86 / PA-6)');
  console.log('────────────────────────────────────────────────────────────');
  await seed();
  console.log('────────────────────────────────────────────────────────────');
  console.log(`Demo-Mandant:  VectiScan Demo GmbH`);
  console.log(`Demo-Login:    ${DEMO_EMAIL}`);
  console.log(`Passwort:      ${process.env.DEMO_PASSWORD || 'VectiScanDemo2026!'}`);
  console.log('Fertig. 3 Reports (WebCheck, Perimeter, Compliance) geseedet.');
  await pool.end();
}

main().catch((err) => {
  console.error('Demo-Seed fehlgeschlagen:', err);
  pool.end().finally(() => process.exit(1));
});
