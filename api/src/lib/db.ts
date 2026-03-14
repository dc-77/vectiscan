import pg from 'pg';
import path from 'path';
import fs from 'fs';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://vectiscan:devpassword@localhost:5432/vectiscan',
});

const MIGRATION_003_PATH = path.join(__dirname, '..', 'migrations', '003_mvp_schema.sql');
const MIGRATION_004_PATH = path.join(__dirname, '..', 'migrations', '004_add_manual_verification.sql');

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
}

export async function query<T extends pg.QueryResultRow = Record<string, unknown>>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params);
}
