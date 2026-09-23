import fs from 'fs';
import path from 'path';

// S6a: reports.report_number, die Berichtsnummer vom Deckblatt
// (VS-<Jahr>-<MMTT>-<Order[:4]>). Additiv und nullable wie Migration 044 bis
// 046; zusaetzlich ohne UNIQUE, weil alle Versionen eines Auftrags dieselbe
// Nummer tragen.

const migrationsDir = path.join(__dirname, '..', 'migrations');
const dbPath = path.join(__dirname, '..', 'lib', 'db.ts');
const file = '047_report_number.sql';
const migrationPath = path.join(migrationsDir, file);
const sql = (): string => fs.readFileSync(migrationPath, 'utf-8');
const executable = (): string =>
  sql()
    .split('\n')
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n')
    .toUpperCase();

describe('Migration 047 — reports.report_number (S6a)', () => {
  it('migration file should exist', () => {
    expect(fs.existsSync(migrationPath)).toBe(true);
  });

  it('should add the column additively', () => {
    expect(sql()).toContain('ALTER TABLE reports');
    expect(sql()).toContain('ADD COLUMN IF NOT EXISTS report_number VARCHAR(40) DEFAULT NULL');
  });

  it('should document the column via COMMENT ON COLUMN', () => {
    expect(sql()).toContain('COMMENT ON COLUMN reports.report_number');
  });

  it('must not contain NOT NULL, CHECK, UNIQUE, DROP or UPDATE (rolling deploy safety)', () => {
    const ex = executable();
    expect(ex).not.toContain('NOT NULL');
    expect(ex).not.toContain('CHECK (');
    expect(ex).not.toContain('UNIQUE');
    expect(ex).not.toContain('DROP ');
    expect(ex).not.toContain('UPDATE ');
  });

  it('db.ts should register migration 047 inside a defensive try/catch', () => {
    const db = fs.readFileSync(dbPath, 'utf-8');
    expect(db).toContain('const MIGRATION_047_PATH');
    expect(db).toContain(file);
    expect(db).toContain('Migration 047 FAILED (continuing without it)');
    expect(db).toContain("table_name = 'reports' AND column_name = 'report_number'");

    const idx = db.indexOf('MIGRATION_047_PATH', db.indexOf('Applying Migration 047'));
    const tryIdx = db.lastIndexOf('try {', idx);
    const catchIdx = db.indexOf('Migration 047 FAILED', idx);
    expect(tryIdx).toBeGreaterThan(-1);
    expect(catchIdx).toBeGreaterThan(tryIdx);
  });

  it('the report-worker writes the same column name', () => {
    const worker = fs.readFileSync(
      path.join(__dirname, '..', '..', '..', 'report-worker', 'reporter', 'worker.py'), 'utf-8');
    expect(worker).toContain("column_name = 'report_number'");
    expect(worker).toContain('columns.append("report_number")');
  });
});
