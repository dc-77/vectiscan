import fs from 'fs';
import path from 'path';

// S6b-1 (spec/09 Q15): Kurzname im Kundenkontext. orders.customer_context ist JSONB
// mit flachen Feldern (Migration 045); die Migration fuehrt nur den Spaltenkommentar
// nach und ist damit idempotent. Kein Backfill, kein UPDATE (Rolling-Deploy-Regel).

const migrationsDir = path.join(__dirname, '..', 'migrations');
const dbPath = path.join(__dirname, '..', 'lib', 'db.ts');
const file = '048_customer_context_kurzname.sql';
const migrationPath = path.join(migrationsDir, file);
const sql = (): string => fs.readFileSync(migrationPath, 'utf-8');
const executable = (): string =>
  sql()
    .split('\n')
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n')
    .toUpperCase();

describe('Migration 048 — customer_context.kurzname (S6b-1)', () => {
  it('migration file should exist', () => {
    expect(fs.existsSync(migrationPath)).toBe(true);
  });

  it('documents kurzname in the column comment', () => {
    expect(sql()).toContain('COMMENT ON COLUMN orders.customer_context');
    expect(sql()).toContain('kurzname');
  });

  it('must not change data or schema (only the comment)', () => {
    const ex = executable();
    expect(ex).not.toContain('ALTER TABLE');
    expect(ex).not.toContain('UPDATE ');
    expect(ex).not.toContain('DROP ');
    expect(ex).not.toContain('NOT NULL');
  });

  it('db.ts registers migration 048 defensively and idempotently', () => {
    const db = fs.readFileSync(dbPath, 'utf-8');
    expect(db).toContain('const MIGRATION_048_PATH');
    expect(db).toContain(file);
    expect(db).toContain('Migration 048 FAILED (continuing without it)');
    expect(db).toContain("LIKE '%kurzname%'");

    const idx = db.indexOf('MIGRATION_048_PATH', db.indexOf('Applying Migration 048'));
    const tryIdx = db.lastIndexOf('try {', idx);
    const catchIdx = db.indexOf('Migration 048 FAILED', idx);
    expect(tryIdx).toBeGreaterThan(-1);
    expect(catchIdx).toBeGreaterThan(tryIdx);
  });
});
