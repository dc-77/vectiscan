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
