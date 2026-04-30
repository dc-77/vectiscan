-- ============================================================================
-- Migration 014: Severity-Policy-Provenance auf report_findings_data
-- ============================================================================
-- Spec: docs/specs/2026-Q2-determinism/05-schema-migrations.md
--
-- Fügt Spalten hinzu für die Nachvollziehbarkeit der Severity-Vergabe
-- durch severity_policy.py:
--   - policy_version       TEXT     ← Version der angewendeten Policy
--   - policy_id_distinct   TEXT[]   ← Liste der policy_ids im Report (für Audit-Queries)
--   - severity_counts      JSONB    ← Generated column für schnelle Aggregation
--
-- Idempotent: re-run-safe via IF NOT EXISTS.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Spalten hinzufügen
-- ----------------------------------------------------------------------------
ALTER TABLE report_findings_data
    ADD COLUMN IF NOT EXISTS policy_version TEXT,
    ADD COLUMN IF NOT EXISTS policy_id_distinct TEXT[];

-- ----------------------------------------------------------------------------
-- 2. Generated Column für severity_counts
--    (PostgreSQL 12+ erforderlich für GENERATED ... STORED)
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'report_findings_data'
        AND column_name = 'severity_counts'
    ) THEN
        ALTER TABLE report_findings_data
            ADD COLUMN severity_counts JSONB
            GENERATED ALWAYS AS (
                jsonb_build_object(
                    'critical', (
                        SELECT count(*)
                        FROM jsonb_array_elements(findings_data) f
                        WHERE f->>'severity' = 'critical'
                    ),
                    'high', (
                        SELECT count(*)
                        FROM jsonb_array_elements(findings_data) f
                        WHERE f->>'severity' = 'high'
                    ),
                    'medium', (
                        SELECT count(*)
                        FROM jsonb_array_elements(findings_data) f
                        WHERE f->>'severity' = 'medium'
                    ),
                    'low', (
                        SELECT count(*)
                        FROM jsonb_array_elements(findings_data) f
                        WHERE f->>'severity' = 'low'
                    ),
                    'info', (
                        SELECT count(*)
                        FROM jsonb_array_elements(findings_data) f
                        WHERE f->>'severity' = 'info'
                    )
                )
            ) STORED;
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- 3. Indexes
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_findings_policy_version
    ON report_findings_data(policy_version);

CREATE INDEX IF NOT EXISTS idx_findings_policy_ids
    ON report_findings_data USING gin(policy_id_distinct);

-- severity_counts ist generated; GIN-Index für JSONB-Queries
CREATE INDEX IF NOT EXISTS idx_findings_severity_counts
    ON report_findings_data USING gin(severity_counts jsonb_path_ops);

-- ----------------------------------------------------------------------------
-- 4. Migrations-Eintrag
-- ----------------------------------------------------------------------------
-- TODO(claude-code): Falls eure migrations-Tabelle anders heißt
-- (z.B. schema_migrations, knex_migrations), hier anpassen.
-- Die `version` ist int — bei TEXT-Schema entsprechend casten.
INSERT INTO migrations (version, applied_at)
VALUES (14, NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;

-- ============================================================================
-- Rollback (manuell ausführen falls nötig)
-- ============================================================================
-- BEGIN;
--   ALTER TABLE report_findings_data
--       DROP COLUMN IF EXISTS severity_counts,
--       DROP COLUMN IF EXISTS policy_id_distinct,
--       DROP COLUMN IF EXISTS policy_version;
--   DROP INDEX IF EXISTS idx_findings_policy_version;
--   DROP INDEX IF EXISTS idx_findings_policy_ids;
--   DROP INDEX IF EXISTS idx_findings_severity_counts;
--   DELETE FROM migrations WHERE version = 14;
-- COMMIT;
