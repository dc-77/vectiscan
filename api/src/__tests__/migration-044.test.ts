import fs from 'fs';
import path from 'path';

describe('Migration 044 — scan_results run status (A7)', () => {
  const migrationPath = path.join(__dirname, '..', 'migrations', '044_scan_results_run_status.sql');
  const dbPath = path.join(__dirname, '..', 'lib', 'db.ts');

  const sql = (): string => fs.readFileSync(migrationPath, 'utf-8');

  it('migration file should exist', () => {
    expect(fs.existsSync(migrationPath)).toBe(true);
  });

  it('should add status and skip_reason additively', () => {
    const content = sql();
    expect(content).toContain('ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT NULL');
    expect(content).toContain('ADD COLUMN IF NOT EXISTS skip_reason VARCHAR(160) DEFAULT NULL');
  });

  it('should create the order/status index idempotently', () => {
    expect(sql()).toContain('CREATE INDEX IF NOT EXISTS idx_scan_results_order_status');
  });

  it('should document the status vocabulary via COMMENT ON COLUMN', () => {
    const content = sql();
    expect(content).toContain('COMMENT ON COLUMN scan_results.status');
    expect(content).toContain('COMMENT ON COLUMN scan_results.skip_reason');
    for (const value of ['ok', 'failed', 'skipped', 'timeout', 'blocked']) {
      expect(content).toContain(value);
    }
  });

  it('must not contain NOT NULL, CHECK, DROP or UPDATE (rolling deploy safety)', () => {
    // Kommentarzeilen (inkl. Rollback-Block) ausblenden — dort stehen
    // DROP-Statements bewusst als Doku.
    const executable = sql()
      .split('\n')
      .filter((line) => !line.trim().startsWith('--'))
      .join('\n')
      .toUpperCase();

    expect(executable).not.toContain('NOT NULL');
    expect(executable).not.toContain('CHECK (');
    expect(executable).not.toContain('DROP ');
    expect(executable).not.toContain('UPDATE ');
  });

  it('db.ts should register migration 044 inside a defensive try/catch', () => {
    const db = fs.readFileSync(dbPath, 'utf-8');
    expect(db).toContain("const MIGRATION_044_PATH");
    expect(db).toContain('044_scan_results_run_status.sql');
    expect(db).toContain('Migration 044 FAILED (continuing without it)');

    // Existence-Check-Muster wie bei Migration 028
    expect(db).toContain("table_name = 'scan_results' AND column_name = 'status'");

    const idx = db.indexOf('MIGRATION_044_PATH', db.indexOf('Applying Migration 044'));
    const tryIdx = db.lastIndexOf('try {', idx);
    const catchIdx = db.indexOf('Migration 044 FAILED', idx);
    expect(tryIdx).toBeGreaterThan(-1);
    expect(catchIdx).toBeGreaterThan(tryIdx);
  });
});
