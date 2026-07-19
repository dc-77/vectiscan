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
const MIGRATION_021_PATH = path.join(__dirname, '..', 'migrations', '021_vpn_strategy.sql');
const MIGRATION_022_PATH = path.join(__dirname, '..', 'migrations', '022_ai_call_costs.sql');
const MIGRATION_023_PATH = path.join(__dirname, '..', 'migrations', '023_consolidated_findings_vhost.sql');
const MIGRATION_024_PATH = path.join(__dirname, '..', 'migrations', '024_determinism_kpi.sql');
const MIGRATION_025_PATH = path.join(__dirname, '..', 'migrations', '025_subscription_delete_safe.sql');
const MIGRATION_026_PATH = path.join(__dirname, '..', 'migrations', '026_shodan_pre_warm.sql');
const MIGRATION_027_PATH = path.join(__dirname, '..', 'migrations', '027_tech_profiles_and_additional_findings.sql');
const MIGRATION_028_PATH = path.join(__dirname, '..', 'migrations', '028_validation_warnings.sql');
const MIGRATION_029_PATH = path.join(__dirname, '..', 'migrations', '029_finding_overrides.sql');
const MIGRATION_030_PATH = path.join(__dirname, '..', 'migrations', '030_stripe_payment_flow.sql');
const MIGRATION_031_PATH = path.join(__dirname, '..', 'migrations', '031_stripe_followup_hardening.sql');
const MIGRATION_032_PATH = path.join(__dirname, '..', 'migrations', '032_lead_capture.sql');
const MIGRATION_033_PATH = path.join(__dirname, '..', 'migrations', '033_analytics_events.sql');
const MIGRATION_034_PATH = path.join(__dirname, '..', 'migrations', '034_webcheck_leads.sql');
const MIGRATION_035_PATH = path.join(__dirname, '..', 'migrations', '035_email_suppressions.sql');
const MIGRATION_036_PATH = path.join(__dirname, '..', 'migrations', '036_reports_expires_at_default.sql');
const MIGRATION_037_PATH = path.join(__dirname, '..', 'migrations', '037_webcheck_marketing_consent.sql');
const MIGRATION_038_PATH = path.join(__dirname, '..', 'migrations', '038_webcheck_consent_not_given.sql');
const MIGRATION_039_PATH = path.join(__dirname, '..', 'migrations', '039_user_authorization_consent.sql');
const MIGRATION_040_PATH = path.join(__dirname, '..', 'migrations', '040_live_check_audit.sql');
const MIGRATION_041_PATH = path.join(__dirname, '..', 'migrations', '041_order_onetime_payment.sql');
const MIGRATION_042_PATH = path.join(__dirname, '..', 'migrations', '042_target_limit_default.sql');

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

  // Migration 021: VPN-Strategy + vpn_activations Audit (PR-VPN).
  const vpn021Check = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'subscriptions' AND column_name = 'vpn_strategy'
    ) AS exists
  `);
  if (!vpn021Check.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_021_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 022: ai_call_costs Tabelle (PR-KI-Optim).
  const aiCosts022Check = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables
      WHERE table_name = 'ai_call_costs'
    ) AS exists
  `);
  if (!aiCosts022Check.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_022_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 023: consolidated_findings.vhost (Multi-VHost-Probe).
  const vhost023Check = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'consolidated_findings' AND column_name = 'vhost'
    ) AS exists
  `);
  if (!vhost023Check.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_023_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 024: subscription_posture.determinism_score (Drift-KPI).
  const det024Check = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'subscription_posture' AND column_name = 'determinism_score'
    ) AS exists
  `);
  if (!det024Check.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_024_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 025: orders.subscription_id ON DELETE SET NULL.
  // Existence-Check: information_schema.referential_constraints — wir
  // pruefen ob die FK aktuell SET NULL hat. Bei NO ACTION/RESTRICT muss
  // umgestellt werden.
  const fk025Check = await pool.query(`
    SELECT delete_rule
      FROM information_schema.referential_constraints
     WHERE constraint_name = 'orders_subscription_id_fkey'
  `);
  const currentRule = fk025Check.rows[0]?.delete_rule;
  if (currentRule && currentRule !== 'SET NULL') {
    const migrationSql = fs.readFileSync(MIGRATION_025_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 026: Shodan Pre-Warm-Felder (subscriptions.shodan_scan_request,
  // orders.pre_warm_requested) — F-P0A-006.
  const preWarm026Check = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'orders' AND column_name = 'pre_warm_requested'
    ) AS exists
  `);
  if (!preWarm026Check.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_026_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 027: tech_profiles + additional_findings auf reports.
  // Quelle fuer Per-Host-Tech-Tabelle (UI + PDF) und "alle Befunde
  // anzeigen"-Drilldown ueber den Top-N-Cap hinaus.
  const techProfiles027Check = await pool.query(`
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = 'reports' AND column_name = 'tech_profiles'
    ) AS exists
  `);
  if (!techProfiles027Check.rows[0].exists) {
    const migrationSql = fs.readFileSync(MIGRATION_027_PATH, 'utf-8');
    await pool.query(migrationSql);
  }

  // Migration 028 (M1, Q2/2026): validation_warnings JSONB auf reports.
  // Defensive try/catch: falls die Migration aus irgendeinem Grund scheitert
  // (Permissions, transient DB-Issue, Filesystem-Quirk), soll der API-Start
  // nicht in eine Restart-Loop fallen — der Report-Worker uebernimmt
  // validation_warnings auch ohne diese Spalte (Feature degradiert dann).
  try {
    const validationWarnings028Check = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.columns
        WHERE table_name = 'reports' AND column_name = 'validation_warnings'
      ) AS exists
    `);
    if (!validationWarnings028Check.rows[0].exists) {
      console.log('[initDb] Applying Migration 028: validation_warnings JSONB');
      const migrationSql = fs.readFileSync(MIGRATION_028_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 028 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 028 FAILED (continuing without it):', err);
  }

  // Migration 029 (Mai 2026): finding_overrides — Admin korrigiert
  // Findings pro-Field (cvss_score, severity, title) oder markiert sie
  // als geprueft (_ignored). Re-Render via regenerate-report appliziert
  // diese Overrides vor PDF.
  try {
    const findingOverrides029Check = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'finding_overrides'
      ) AS exists
    `);
    if (!findingOverrides029Check.rows[0].exists) {
      console.log('[initDb] Applying Migration 029: finding_overrides');
      const migrationSql = fs.readFileSync(MIGRATION_029_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 029 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 029 FAILED (continuing without it):', err);
  }

  // Migration 030 (PA-1 / VEC-33): Stripe Live Payment Flow — paid_at +
  // stripe_checkout_session_id + status 'payment_failed' auf subscriptions
  // sowie stripe_webhook_events (Idempotenz-Ledger).
  try {
    const stripeEvents030Check = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'stripe_webhook_events'
      ) AS exists
    `);
    if (!stripeEvents030Check.rows[0].exists) {
      console.log('[initDb] Applying Migration 030: stripe_payment_flow');
      const migrationSql = fs.readFileSync(MIGRATION_030_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 030 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 030 FAILED (continuing without it):', err);
  }

  // Migration 031 (VEC-112): Stripe-Follow-up-Haertung — idempotenter
  // Enqueue-Claim-Marker scan_targets.precheck_enqueued_at (L1 Atomicitaet).
  try {
    const precheckColCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.columns
        WHERE table_name = 'scan_targets' AND column_name = 'precheck_enqueued_at'
      ) AS exists
    `);
    if (!precheckColCheck.rows[0].exists) {
      console.log('[initDb] Applying Migration 031: stripe_followup_hardening');
      const migrationSql = fs.readFileSync(MIGRATION_031_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 031 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 031 FAILED (continuing without it):', err);
  }

  // Migration 032 (Juni 2026): leads — Lead-Capture/Demo-Anfragen (VEC-36).
  // Eingehende Leads werden persistiert, BEVOR die E-Mail-Zustellung an den
  // Vertrieb versucht wird, damit kein Lead verloren geht.
  try {
    const leads032Check = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'leads'
      ) AS exists
    `);
    if (!leads032Check.rows[0].exists) {
      console.log('[initDb] Applying Migration 032: leads');
      const migrationSql = fs.readFileSync(MIGRATION_032_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 032 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 032 FAILED (continuing without it):', err);
  }

  // Migration 033 (Juni 2026): analytics_events — cookieloses, DSGVO-freundliches
  // First-Party-Traffic-Tracking ohne personenbezogene Daten (VEC-36).
  try {
    const analytics033Check = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'analytics_events'
      ) AS exists
    `);
    if (!analytics033Check.rows[0].exists) {
      console.log('[initDb] Applying Migration 033: analytics_events');
      const migrationSql = fs.readFileSync(MIGRATION_033_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 033 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 033 FAILED (continuing without it):', err);
  }

  // Migration 034 (VEC-91): WebCheck-Free Lead-Magnet — separate Lead-/Marketing-
  // Tabelle webcheck_leads (DSGVO-Datentrennung). Additiv, idempotent.
  try {
    const webcheckLeadsCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables WHERE table_name = 'webcheck_leads'
      ) AS exists
    `);
    if (!webcheckLeadsCheck.rows[0].exists) {
      console.log('[initDb] Applying Migration 034: webcheck_leads');
      const migrationSql = fs.readFileSync(MIGRATION_034_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 034 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 034 FAILED (continuing without it):', err);
  }

  // Migration 035 (VEC-188): E-Mail-Suppression-Liste + Resend-Webhook-Idempotenz-
  // Ledger (Reputationsschutz aus VEC-173/F2). Additiv, idempotent.
  try {
    const suppressions035Check = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables WHERE table_name = 'email_suppressions'
      ) AS exists
    `);
    if (!suppressions035Check.rows[0].exists) {
      console.log('[initDb] Applying Migration 035: email_suppressions');
      const migrationSql = fs.readFileSync(MIGRATION_035_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 035 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 035 FAILED (continuing without it):', err);
  }

  // Migration 036 (VEC-180): Default-TTL (30 Tage) auf reports.expires_at —
  // Defense-in-Depth gegen nie ablaufende anonyme Report-Deeplinks (CL-1/VEC-169).
  // Idempotent: nur anwenden, wenn noch kein column_default gesetzt ist.
  try {
    const expiresDefaultCheck = await pool.query(`
      SELECT column_default
      FROM information_schema.columns
      WHERE table_name = 'reports' AND column_name = 'expires_at'
    `);
    const currentDefault = expiresDefaultCheck.rows[0]?.column_default ?? null;
    if (!currentDefault) {
      console.log('[initDb] Applying Migration 036: reports.expires_at default (30d)');
      const migrationSql = fs.readFileSync(MIGRATION_036_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 036 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 036 FAILED (continuing without it):', err);
  }

  // Migration 037 (VEC-173): WebCheck-Marketing-Einwilligung als Art.-7-Nachweis
  // (marketing_consent + consent_text_version). Idempotent: nur anwenden, wenn die
  // Spalte marketing_consent auf webcheck_leads noch fehlt.
  try {
    const consentColCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.columns
        WHERE table_name = 'webcheck_leads' AND column_name = 'marketing_consent'
      ) AS exists
    `);
    if (!consentColCheck.rows[0].exists) {
      console.log('[initDb] Applying Migration 037: webcheck marketing_consent');
      const migrationSql = fs.readFileSync(MIGRATION_037_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 037 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 037 FAILED (continuing without it):', err);
  }

  // Migration 038 (VEC-198): consent_status 'not_given' (nie eingewilligt) vom
  // echten 'declined' (aktive Ablehnung) trennen — CHECK-Erweiterung. Idempotent:
  // nur anwenden, wenn der bestehende consent_status-CHECK 'not_given' noch nicht
  // erlaubt.
  try {
    const notGivenCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE rel.relname = 'webcheck_leads'
          AND con.contype = 'c'
          AND pg_get_constraintdef(con.oid) ILIKE '%not_given%'
      ) AS exists
    `);
    if (!notGivenCheck.rows[0].exists) {
      console.log('[initDb] Applying Migration 038: webcheck consent_status not_given');
      const migrationSql = fs.readFileSync(MIGRATION_038_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 038 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 038 FAILED (continuing without it):', err);
  }

  // Migration 039 (VEC-364): verpflichtende, versionierte Scan-Berechtigungs-
  // Bestätigung am Konto (authorization_consent_version + _at). Idempotent: nur
  // anwenden, wenn die Spalte authorization_consent_version auf users noch fehlt.
  try {
    const authConsentColCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'authorization_consent_version'
      ) AS exists
    `);
    if (!authConsentColCheck.rows[0].exists) {
      console.log('[initDb] Applying Migration 039: user authorization_consent');
      const migrationSql = fs.readFileSync(MIGRATION_039_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 039 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 039 FAILED (continuing without it):', err);
  }

  // Migration 040 (VEC-363): Live-Check-Scan-Audit-Log (live_check_audit).
  // Idempotent: nur anwenden, wenn die Tabelle noch fehlt.
  try {
    const liveCheckAuditCheck = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_name = 'live_check_audit'
      ) AS exists
    `);
    if (!liveCheckAuditCheck.rows[0].exists) {
      console.log('[initDb] Applying Migration 040: live_check_audit');
      const migrationSql = fs.readFileSync(MIGRATION_040_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 040 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 040 FAILED (continuing without it):', err);
  }

  // Migration 041 (VEC-436): Stripe Einzelscan-Checkout (mode=payment) —
  // orders.payment_status + orders.stripe_checkout_session_id +
  // stripe_webhook_events.order_id. Idempotent: nur anwenden, wenn die
  // payment_status-Spalte noch fehlt.
  try {
    const orderPayment041Check = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.columns
        WHERE table_name = 'orders' AND column_name = 'payment_status'
      ) AS exists
    `);
    if (!orderPayment041Check.rows[0].exists) {
      console.log('[initDb] Applying Migration 041: order_onetime_payment');
      const migrationSql = fs.readFileSync(MIGRATION_041_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 041 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 041 FAILED (continuing without it):', err);
  }

  // Migration 042: Standard-Target-Limit pro Abo auf 5 senken (Zielbild Juli 2026).
  // Idempotent ueber den aktuellen Spalten-Default (30 -> 5).
  try {
    const maxDomainsDefault042Check = await pool.query(`
      SELECT column_default FROM information_schema.columns
      WHERE table_name = 'subscriptions' AND column_name = 'max_domains'
    `);
    const curDefault = (maxDomainsDefault042Check.rows[0]?.column_default ?? '').toString().trim();
    if (curDefault !== '' && curDefault !== '5') {
      console.log('[initDb] Applying Migration 042: target_limit_default (max_domains -> 5)');
      const migrationSql = fs.readFileSync(MIGRATION_042_PATH, 'utf-8');
      await pool.query(migrationSql);
      console.log('[initDb] Migration 042 applied');
    }
  } catch (err) {
    console.error('[initDb] Migration 042 FAILED (continuing without it):', err);
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

/** Eine an einen Transaktions-Client gebundene query-Funktion. */
export type TxQuery = <T extends pg.QueryResultRow = Record<string, unknown>>(
  text: string,
  params?: unknown[],
) => Promise<pg.QueryResult<T>>;

/**
 * Fuehrt `fn` in einer DB-Transaktion aus (BEGIN/COMMIT, ROLLBACK bei Fehler).
 * `fn` erhaelt eine an den Transaktions-Client gebundene query-Funktion —
 * alle darueber abgesetzten Statements committen bzw. rollbacken gemeinsam.
 *
 * Wird (VEC-112/L1) genutzt, um Abo-Aktivierung + Scan-Kontingent-Enqueue
 * atomar zu machen: schlaegt das Enqueue fehl, rollt auch die Aktivierung
 * zurueck, sodass der Stripe-Retry sauber von vorne aufsetzt (kein bezahltes
 * Abo ohne Scan-Kontingent).
 */
export async function withTransaction<T>(fn: (q: TxQuery) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const q: TxQuery = (text, params) => client.query(text, params);
    const result = await fn(q);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // ROLLBACK-Fehler nicht ueber den eigentlichen Fehler maskieren.
    }
    throw err;
  } finally {
    client.release();
  }
}
