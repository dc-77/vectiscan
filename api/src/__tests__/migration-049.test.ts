import fs from 'fs';
import path from 'path';

// S6b-2: reports.delivery_version (Auslieferungsversion auf dem Deckblatt) und
// finding_exclusions.finding_key (stabiler Befundschluessel, Issue #28). Additiv und
// nullable wie Migration 044 bis 048.

const migrationsDir = path.join(__dirname, '..', 'migrations');
const dbPath = path.join(__dirname, '..', 'lib', 'db.ts');
const ordersPath = path.join(__dirname, '..', 'routes', 'orders.ts');
const workerPath = path.join(__dirname, '..', '..', '..', 'report-worker', 'reporter', 'worker.py');
const file = '049_delivery_version_finding_key.sql';
const migrationPath = path.join(migrationsDir, file);
const sql = (): string => fs.readFileSync(migrationPath, 'utf-8');
const executable = (): string =>
  sql()
    .split('\n')
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n')
    .toUpperCase();

describe('Migration 049 — delivery_version und finding_key (S6b-2)', () => {
  it('migration file should exist', () => {
    expect(fs.existsSync(migrationPath)).toBe(true);
  });

  it('should add both columns additively', () => {
    expect(sql()).toContain('ADD COLUMN IF NOT EXISTS delivery_version INTEGER DEFAULT NULL');
    expect(sql()).toContain('ADD COLUMN IF NOT EXISTS finding_key TEXT DEFAULT NULL');
  });

  it('should document both columns via COMMENT ON COLUMN', () => {
    expect(sql()).toContain('COMMENT ON COLUMN reports.delivery_version');
    expect(sql()).toContain('COMMENT ON COLUMN finding_exclusions.finding_key');
  });

  it('must not contain NOT NULL, CHECK, UNIQUE, DROP or UPDATE (rolling deploy safety)', () => {
    const ex = executable();
    expect(ex).not.toContain('NOT NULL');
    expect(ex).not.toContain('CHECK (');
    expect(ex).not.toContain('UNIQUE');
    expect(ex).not.toContain('DROP ');
    expect(ex).not.toContain('UPDATE ');
  });

  it('db.ts should register migration 049 inside a defensive try/catch', () => {
    const db = fs.readFileSync(dbPath, 'utf-8');
    expect(db).toContain('const MIGRATION_049_PATH');
    expect(db).toContain(file);
    expect(db).toContain('Migration 049 FAILED (continuing without it)');
    expect(db).toContain("table_name = 'reports' AND column_name = 'delivery_version'");
    expect(db).toContain("table_name = 'finding_exclusions' AND column_name = 'finding_key'");

    const idx = db.indexOf('MIGRATION_049_PATH', db.indexOf('Applying Migration 049'));
    const tryIdx = db.lastIndexOf('try {', idx);
    const catchIdx = db.indexOf('Migration 049 FAILED', idx);
    expect(tryIdx).toBeGreaterThan(-1);
    expect(catchIdx).toBeGreaterThan(tryIdx);
  });

  it('der Ausschluss speichert den Schluessel und faellt ohne Spalte auf die Nummer zurueck', () => {
    const orders = fs.readFileSync(ordersPath, 'utf-8');
    expect(orders).toContain('async function currentFindingKey(');
    expect(orders).toContain('INSERT INTO finding_exclusions (order_id, finding_id, excluded_by, reason, finding_key)');
    // 42703 = undefined_column: Migration 049 fehlt, der Ausschluss gilt ueber die Nummer.
    expect(orders).toContain("code !== '42703'");
    // Freigabe und Neuerzeugung reichen den Schluessel an den report-worker weiter.
    expect(orders.match(/finding_key: r\.finding_key \?\? null/g)?.length).toBe(2);
  });

  it('der report-worker schreibt und liest dieselben Spaltennamen', () => {
    const worker = fs.readFileSync(workerPath, 'utf-8');
    expect(worker).toContain("column_name = 'delivery_version'");
    expect(worker).toContain('columns.append("delivery_version")');
    expect(worker).toContain('item.get("finding_key")');
  });
});
