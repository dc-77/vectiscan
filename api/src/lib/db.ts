import pg from 'pg';
import path from 'path';
import fs from 'fs';
import { hashPassword } from './auth.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://vectiscan:devpassword@localhost:5432/vectiscan',
});

const MIGRATION_003_PATH = path.join(__dirname, '..', 'migrations', '003_mvp_schema.sql');
const MIGRATION_004_PATH = path.join(__dirname, '..', 'migrations', '004_add_manual_verification.sql');
const MIGRATION_005_PATH = path.join(__dirname, '..', 'migrations', '005_users.sql');
const MIGRATION_006_PATH = path.join(__dirname, '..', 'migrations', '006_password_reset.sql');
const MIGRATION_007_PATH = path.join(__dirname, '..', 'migrations', '007_report_findings_data.sql');
const MIGRATION_008_PATH = path.join(__dirname, '..', 'migrations', '008_scan_schedules.sql');
const MIGRATION_009_PATH = path.join(__dirname, '..', 'migrations', '009_v2_packages.sql');
const MIGRATION_010_PATH = path.join(__dirname, '..', 'migrations', '010_verified_domains.sql');
const MIGRATION_011_PATH = path.join(__dirname, '..', 'migrations', '011_finding_exclusions_report_versioning.sql');
const MIGRATION_012_PATH = path.join(__dirname, '..', 'migrations', '012_subscriptions_review_workflow.sql');
const MIGRATION_013_PATH = path.join(__dirname, '..', 'migrations', '013_company_name.sql');
const MIGRATION_014_PATH = path.join(__dirname, '..', 'migrations', '014_multi_target.sql');
const MIGRATION_015_PATH = path.join(__dirname, '..', 'migrations', '015_performance_metrics.sql');
const MIGRATION_016_PATH = path.join(__dirname, '..', 'migrations', '016_severity_policy.sql');
const MIGRATION_017_PATH = path.join(__dirname, '..', 'migrations', '017_threat_intel_snapshots.sql');
const MIGRATION_018_PATH = path.join(__dirname, '..', 'migrations', '018_severity_counts_trigger_fix.sql');
const MIGRATION_019_PATH = path.join(__dirname, '..', 'migrations', '019_subdomain_snapshot.sql');
const MIGRATION_020_PATH = path.join(__dirname, '..', 'migrations', '020_subscription_posture.sql');

export async function initDb(): Promise<void> {
  // Check if MVP migration has been applied (orders table exists)
  const check = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables WHERE table_name = 'orders'
    ) AS exists
  `);

  if (!check.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_003_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 004: Add 'manual' to verification_method constraint
  try {
    const constraintCheck = await pool.query(`
      SELECT pg_get_constraintdef(oid) AS def
      FROM pg_constraint
      WHERE conname = 'chk_orders_verification_method'
    `);
    const def = constraintCheck.rows[0]?.def || '';
    if (!def.includes('manual')) {
      const migrationSql = fs.readFileSync(MIGRATION_004_PATH, 'utf-8');
      await pool.query(migrationSql);
    }
  } catch {
    // Constraint doesn't exist yet — 003 will create it with 'manual' included
  }

  // Migration 005: Users table
  const usersCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables WHERE table_name = 'users'
    ) AS exists
  `);

  if (!usersCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_005_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 006: Password reset columns on users
  const resetColCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'users' AND column_name = 'reset_token'
    ) AS exists
  `);

  if (!resetColCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_006_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 007: findings_data JSONB on reports
  const findingsColCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'reports' AND column_name = 'findings_data'
    ) AS exists
  `);

  if (!findingsColCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_007_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 008: scan_schedules table
  const schedulesCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables WHERE table_name = 'scan_schedules'
    ) AS exists
  `);

  if (!schedulesCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_008_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 009: v2 packages (3→5) + new columns for Phase 0a/Phase 3
  const v2ColCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'orders' AND column_name = 'business_impact_score'
    ) AS exists
  `);

  if (!v2ColCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_009_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 010: verified_domains table
  const verifiedDomainsCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables WHERE table_name = 'verified_domains'
    ) AS exists
  `);

  if (!verifiedDomainsCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_010_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 011: finding_exclusions + report versioning
  const exclusionsCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables WHERE table_name = 'finding_exclusions'
    ) AS exists
  `);

  if (!exclusionsCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_011_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 012: subscriptions + review workflow
  const subscriptionsCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables WHERE table_name = 'subscriptions'
    ) AS exists
  `);

  if (!subscriptionsCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_012_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 013: company_name on customers
  const companyColCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'customers' AND column_name = 'company_name'
    ) AS exists
  `);

  if (!companyColCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_013_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 014: Multi-Target scan orchestration
  const multiTargetCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables WHERE table_name = 'scan_targets'
    ) AS exists
  `);

  if (!multiTargetCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_014_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 015: performance_metrics JSONB on orders
  const perfMetricsColCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'orders' AND column_name = 'performance_metrics'
    ) AS exists
  `);

  if (!perfMetricsColCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_015_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 016: Severity-Policy-Provenance auf reports (policy_version, policy_id_distinct, severity_counts)
  const policyVersionColCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'reports' AND column_name = 'policy_version'
    ) AS exists
  `);

  if (!policyVersionColCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_016_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 017: Threat-Intel-Snapshots-Tabelle + orders.threat_intel_snapshot_id
  const tiSnapshotsCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables WHERE table_name = 'threat_intel_snapshots'
    ) AS exists
  `);

  if (!tiSnapshotsCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_017_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 018: Trigger-Fix fuer severity_counts (016 las den falschen JSONB-Pfad).
  // Existence-Check: prueft ob die Trigger-Funktion das richtige `findings_data->'findings'`
  // referenziert. Wenn nein → Migration anwenden (CREATE OR REPLACE + Backfill, idempotent).
  const triggerFnDefCheck = await pool.query(`
    SELECT pg_get_functiondef(p.oid) AS def
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE p.proname = 'reports_update_severity_counts'
       AND n.nspname = 'public'
     LIMIT 1
  `);

  const triggerDef = (triggerFnDefCheck.rows[0]?.def as string | undefined) ?? '';
  if (!triggerDef.includes("findings_data->'findings'")) {
    const migrationSql = fs.readFileSync(MIGRATION_018_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 019: Subdomain-Snapshot pro scan_target (PR-M4).
  const subdomainSnapshotCheck = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables
      WHERE table_name = 'scan_target_subdomain_snapshots'
    ) AS exists
  `);
  if (!subdomainSnapshotCheck.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_019_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 020: Subscription-Posture-Modell (Multi-Scan-Aggregation).
  const posture020Check = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables
      WHERE table_name = 'subscription_posture'
    ) AS exists
  `);
  if (!posture020Check.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_020_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Seed admin account if configured and not yet created
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  if (adminEmail && adminPassword) {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [adminEmail.toLowerCase()]);
    if (existing.rows.length === 0) {
      const passwordHash = await hashPassword(adminPassword);
      await pool.query(
        "INSERT INTO users (email, password_hash, role) VALUES ($1, $2, 'admin')",
        [adminEmail.toLowerCase(), passwordHash],
      );
    }
  }
}

export async function query<T extends pg.QueryResultRow = Record<string, unknown>>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params);
}
