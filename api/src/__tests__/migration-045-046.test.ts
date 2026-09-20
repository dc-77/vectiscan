import fs from 'fs';
import path from 'path';

// S5: Zwei additive jsonb-Spalten auf orders. Der Aufbau folgt Migration 044:
// kein NOT NULL, kein CHECK, kein Backfill, weil waehrend des Rolling-Deploys
// alte Images weiterlaufen, die die Spalten nicht kennen.

const migrationsDir = path.join(__dirname, '..', 'migrations');
const dbPath = path.join(__dirname, '..', 'lib', 'db.ts');

const MIGRATIONS = [
  { nr: '045', file: '045_customer_context.sql', column: 'customer_context' },
  { nr: '046', file: '046_report_defects.sql', column: 'report_defects' },
] as const;

describe.each(MIGRATIONS)('Migration $nr — orders.$column (S5)', ({ nr, file, column }) => {
  const migrationPath = path.join(migrationsDir, file);
  const sql = (): string => fs.readFileSync(migrationPath, 'utf-8');

  it('migration file should exist', () => {
    expect(fs.existsSync(migrationPath)).toBe(true);
  });

  it('should add the column additively', () => {
    expect(sql()).toContain(`ADD COLUMN IF NOT EXISTS ${column} JSONB DEFAULT NULL`);
  });

  it('should document the shape via COMMENT ON COLUMN', () => {
    expect(sql()).toContain(`COMMENT ON COLUMN orders.${column}`);
  });

  it('must not contain NOT NULL, CHECK, DROP or UPDATE (rolling deploy safety)', () => {
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

  it(`db.ts should register migration ${nr} inside a defensive try/catch`, () => {
    const db = fs.readFileSync(dbPath, 'utf-8');
    expect(db).toContain(`const MIGRATION_${nr}_PATH`);
    expect(db).toContain(file);
    expect(db).toContain(`Migration ${nr} FAILED (continuing without it)`);
    expect(db).toContain(`table_name = 'orders' AND column_name = '${column}'`);

    const idx = db.indexOf(`MIGRATION_${nr}_PATH`, db.indexOf(`Applying Migration ${nr}`));
    const tryIdx = db.lastIndexOf('try {', idx);
    const catchIdx = db.indexOf(`Migration ${nr} FAILED`, idx);
    expect(tryIdx).toBeGreaterThan(-1);
    expect(catchIdx).toBeGreaterThan(tryIdx);
  });
});

describe('Migration 045/046 — keine Statusmigration noetig', () => {
  it('orders.status traegt weiterhin keine CHECK-Constraint', () => {
    // 014_multi_target.sql haelt das ausdruecklich fest. Waere das anders,
    // muesste report_blocked (S5) in eine Constraint aufgenommen werden.
    const multi = fs.readFileSync(path.join(migrationsDir, '014_multi_target.sql'), 'utf-8');
    expect(multi).toContain('keine CHECK-Constraint auf status');

    const statements = fs.readdirSync(migrationsDir)
      .filter(f => f.endsWith('.sql'))
      .map(f => fs.readFileSync(path.join(migrationsDir, f), 'utf-8'))
      .join('\n')
      .split('\n')
      .filter(line => !line.trim().startsWith('--'))
      .join('\n');

    expect(statements).not.toMatch(/ALTER TABLE orders[\s\S]{0,120}CHECK \(status/i);
  });
});
