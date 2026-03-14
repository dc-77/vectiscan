import pg from 'pg';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://vectiscan:devpassword@localhost:5432/vectiscan',
});

const MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS scans (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain              VARCHAR(255) NOT NULL,
    status              VARCHAR(30) NOT NULL DEFAULT 'created',
    discovered_hosts    JSONB,
    hosts_total         INTEGER DEFAULT 0,
    hosts_completed     INTEGER DEFAULT 0,
    current_phase       VARCHAR(20),
    current_tool        VARCHAR(50),
    current_host        VARCHAR(50),
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    error_message       TEXT,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

CREATE TABLE IF NOT EXISTS scan_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID REFERENCES scans(id) ON DELETE CASCADE,
    host_ip     VARCHAR(50),
    phase       SMALLINT NOT NULL,
    tool_name   VARCHAR(50) NOT NULL,
    raw_output  TEXT,
    exit_code   INTEGER,
    duration_ms INTEGER,
    findings    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id);

CREATE TABLE IF NOT EXISTS reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE UNIQUE,
    minio_bucket    VARCHAR(50) DEFAULT 'scan-reports',
    minio_path      VARCHAR(500) NOT NULL,
    file_size_bytes INTEGER,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
`;

const MIGRATION_002_SQL = `
ALTER TABLE scans ADD COLUMN IF NOT EXISTS package VARCHAR(20) NOT NULL DEFAULT 'professional';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_scans_package'
  ) THEN
    ALTER TABLE scans ADD CONSTRAINT chk_scans_package
      CHECK (package IN ('basic', 'professional', 'nis2'));
  END IF;
END
$$;
`;

export async function initDb(): Promise<void> {
  await pool.query(MIGRATION_SQL);
  await pool.query(MIGRATION_002_SQL);
}

export async function query<T extends pg.QueryResultRow = Record<string, unknown>>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params);
}
