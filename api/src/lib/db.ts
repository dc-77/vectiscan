import pg from 'pg';
import path from 'path';
import fs from 'fs';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://vectiscan:devpassword@localhost:5432/vectiscan',
});

const MIGRATION_003_PATH = path.join(__dirname, '..', 'migrations', '003_mvp_schema.sql');

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
}

export async function query<T extends pg.QueryResultRow = Record<string, unknown>>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params);
}
