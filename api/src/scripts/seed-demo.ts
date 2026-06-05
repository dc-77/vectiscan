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
 * ENV:      DEMO_PASSWORD (Pflicht — kein Default-Fallback mehr, VEC-258/260;
 *           lokal entweder setzen oder bewusst DEMO_ALLOW_WELL_KNOWN_PASSWORD=1)
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

/** Synthetische Host-Telemetrie aus der Fixture (HostInfo-kompatibel). */
interface DemoHost {
  ip: string;
  fqdns: string[];
  status: string;
}

interface Fixture extends DemoFindingsData {
  target: string;
  company_name: string;
  // VEC-245: Determinismus-Provenienz + Host-Telemetrie fuer die KPI-Kacheln.
  // policy_version/policy_id_distinct landen in den reports-Audit-Spalten
  // (Migration 016), hosts in orders.discovered_hosts.
  policy_version?: string;
  policy_id_distinct?: string[];
  hosts?: DemoHost[];
}

function loadFixture(pkg: string): Fixture {
  const file = path.join(__dirname, 'demo-data', `${pkg}.json`);
  return JSON.parse(fs.readFileSync(file, 'utf-8')) as Fixture;
}

/**
 * Strippt Hilfsfelder → exakt das findings_data-Objekt, das auch der
 * Report-Worker speichert. Audit-/Telemetrie-Felder (policy_version,
 * policy_id_distinct, hosts) gehoeren in eigene DB-Spalten, nicht in
 * findings_data, und werden hier entfernt. Die per-Finding-Provenienz
 * (policy_id, severity_provenance) bleibt im findings-Array erhalten.
 */
function toFindingsData(fx: Fixture): Record<string, unknown> {
  const {
    target: _t, company_name: _c,
    policy_version: _pv, policy_id_distinct: _pid, hosts: _h,
    ...rest
  } = fx;
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

/**
 * VEC-258/VEC-260: Demo-Passwort streng aufloesen. Der Seed darf NIEMALS still
 * das oeffentlich dokumentierte Quell-Default seeden (Sven-Auflage VEC-121) —
 * sonst ist auf prod ein allgemein bekanntes Passwort gueltig (Re-Verif-FAIL
 * VEC-260). Verteidigung am Engpass, unabhaengig von der Quelle (CI-Var,
 * Host-Secret oder frueherer Code-Fallback):
 *   - leer/ungesetzt   -> harter Abbruch (kein Default-Fallback mehr)
 *   - == Quell-Default -> harter Abbruch, ausser expliziter Local-Dev-Opt-in
 *     DEMO_ALLOW_WELL_KNOWN_PASSWORD=1
 * Der Default steht hier nur als Denylist-Wert (kein Secret) und in KEINER
 * console.*-Zeile (VEC-153 / CWE-532, Regressionstest demo_seed_no_password_echo).
 */
const WELL_KNOWN_DEFAULT = 'VectiScanDemo2026!';
function resolveDemoPassword(): string {
  const pw = (process.env.DEMO_PASSWORD ?? '').trim();
  if (!pw) {
    console.error(
      'FATAL: DEMO_PASSWORD ist nicht gesetzt. Der Seed verwendet bewusst kein ' +
        'Default mehr (VEC-258). Quelle: maskierte CI/CD-Var DEMO_PASSWORD oder ' +
        'Host-Secret unter DEPLOY_PATH/.demo_password.',
    );
    process.exit(1);
  }
  if (pw === WELL_KNOWN_DEFAULT && process.env.DEMO_ALLOW_WELL_KNOWN_PASSWORD !== '1') {
    console.error(
      'FATAL: DEMO_PASSWORD entspricht dem oeffentlich dokumentierten Quell-Default. ' +
        'Abbruch, um kein allgemein bekanntes Passwort live zu seeden (VEC-260). ' +
        'Fuer lokale Demos bewusst DEMO_ALLOW_WELL_KNOWN_PASSWORD=1 setzen.',
    );
    process.exit(1);
  }
  return pw;
}

async function seed(): Promise<void> {
  const password = resolveDemoPassword();
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

    // VEC-245: Determinismus-Provenienz fuer die Scan-Detail-KPI-Kacheln.
    // policy_id_distinct primaer aus der Fixture; Fallback = aus den Findings
    // abgeleitet (haelt KPI auch ohne explizites Fixture-Feld konsistent).
    const policyVersion = fx.policy_version ?? null;
    const policyIdDistinct =
      fx.policy_id_distinct ??
      [...new Set(fx.findings.map((f) => f.policy_id).filter((p): p is string => !!p))].sort();
    // Host-Telemetrie → orders.discovered_hosts (vom Frontend fuer die
    // Hosts-Kachel gelesen). Anzahl deckt sich mit hosts_total.
    const hosts: DemoHost[] = fx.hosts ?? [];
    const hostsTotal = spec.pkg === 'webcheck' ? 1 : 3;

    // Order — fertig & bezahlt
    await query(
      `INSERT INTO orders (
         id, customer_id, target_url, package, status,
         verification_method, verified_at,
         paid_at, amount_cents, currency,
         scan_started_at, scan_finished_at,
         hosts_total, hosts_completed, target_count,
         discovered_hosts,
         created_at, updated_at
       ) VALUES (
         $1, $2, $3, $4, 'report_complete',
         'manual', $5,
         $5, $6, 'EUR',
         $7, $5,
         $8, $8, 1,
         $9::jsonb,
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
        hostsTotal,
        JSON.stringify(hosts),
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

    // Report-Datensatz (severity_counts-Spalte wird per Trigger aus findings_data abgeleitet).
    // VEC-245: policy_version + policy_id_distinct (Migration 016) befuellen → Determinismus-
    // KPI/Policy-Coverage zeigen plausible Werte statt 0 %.
    await query(
      `INSERT INTO reports (
         id, order_id, minio_bucket, minio_path, file_size_bytes,
         download_token, download_count, expires_at, findings_data,
         policy_version, policy_id_distinct, version, created_at
       ) VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8, $9, $10::text[], 1, $11)`,
      [
        spec.reportId,
        spec.orderId,
        REPORTS_BUCKET,
        objectPath,
        pdf.length,
        spec.downloadToken,
        new Date(new Date(finishedAt).getTime() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        JSON.stringify(findingsData),
        policyVersion,
        policyIdDistinct,
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
  // VEC-153 (Sven/Security, CWE-532): Passwort NICHT ins Log echoen. Bei host-
  // Secret-Fallback (unmaskiert) landete der Klartext sonst im CI-Trace. Quelle
  // bewusst nur benannt, nicht den Wert.
  console.log('Passwort:      [redigiert] — siehe maskierte CI/CD-Variable DEMO_PASSWORD bzw. Host-Secret ${DEPLOY_PATH}/.demo_password');
  console.log('Fertig. 3 Reports (WebCheck, Perimeter, Compliance) geseedet.');
  await pool.end();
}

main().catch((err) => {
  console.error('Demo-Seed fehlgeschlagen:', err);
  pool.end().finally(() => process.exit(1));
});
