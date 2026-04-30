-- ============================================================
-- Migration 016: Severity-Policy-Provenance auf reports
-- ============================================================
-- Spec: docs/deterministic/05-schema-migrations.md (adaptiert)
--
-- Die deterministische Severity-Policy (report-worker/reporter/severity_policy.py)
-- vergibt pro Finding eine policy_id und schreibt severity_provenance ins
-- bestehende reports.findings_data JSONB. Diese Migration ergaenzt drei
-- Audit-Spalten an reports fuer Aggregation und Index-Queries:
--
--   - policy_version       TEXT     ← Version der angewendeten Policy
--   - policy_id_distinct   TEXT[]   ← Liste der policy_ids im Report
--   - severity_counts      JSONB    ← Per Trigger aktualisiert aus findings_data
--
-- HINWEIS zu severity_counts:
-- PostgreSQL erlaubt in GENERATED-Columns keine Subqueries
-- (jsonb_array_elements). Stattdessen befuellt ein BEFORE-INSERT/UPDATE-
-- Trigger die Spalte deterministisch aus findings_data. Damit bleibt
-- die Spalte konsistent ohne dass Applikationscode sie selbst befuellen muss.
--
-- Idempotent: re-run-safe ueber IF NOT EXISTS und Existenz-Checks.
-- ============================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Audit-Spalten an reports
-- ----------------------------------------------------------------------------
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS policy_version TEXT;

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS policy_id_distinct TEXT[];

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS severity_counts JSONB
    DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'::JSONB;

-- ----------------------------------------------------------------------------
-- 2. Trigger-Funktion: severity_counts aus findings_data ableiten
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION reports_update_severity_counts() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.findings_data IS NULL OR jsonb_typeof(NEW.findings_data) <> 'array' THEN
        NEW.severity_counts := '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'::JSONB;
    ELSE
        NEW.severity_counts := jsonb_build_object(
            'critical', (
                SELECT count(*)
                FROM jsonb_array_elements(NEW.findings_data) f
                WHERE lower(f->>'severity') = 'critical'
            ),
            'high', (
                SELECT count(*)
                FROM jsonb_array_elements(NEW.findings_data) f
                WHERE lower(f->>'severity') = 'high'
            ),
            'medium', (
                SELECT count(*)
                FROM jsonb_array_elements(NEW.findings_data) f
                WHERE lower(f->>'severity') = 'medium'
            ),
            'low', (
                SELECT count(*)
                FROM jsonb_array_elements(NEW.findings_data) f
                WHERE lower(f->>'severity') = 'low'
            ),
            'info', (
                SELECT count(*)
                FROM jsonb_array_elements(NEW.findings_data) f
                WHERE lower(f->>'severity') = 'info'
            )
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_reports_update_severity_counts ON reports;

CREATE TRIGGER trg_reports_update_severity_counts
    BEFORE INSERT OR UPDATE OF findings_data ON reports
    FOR EACH ROW
    EXECUTE FUNCTION reports_update_severity_counts();

-- ----------------------------------------------------------------------------
-- 3. Indexe fuer Audit-Queries
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_reports_policy_version
    ON reports(policy_version);

CREATE INDEX IF NOT EXISTS idx_reports_policy_ids
    ON reports USING gin(policy_id_distinct);

CREATE INDEX IF NOT EXISTS idx_reports_severity_counts
    ON reports USING gin(severity_counts jsonb_path_ops);

COMMIT;

-- ============================================================
-- ROLLBACK (manuell, auskommentiert)
-- ============================================================
-- BEGIN;
--   DROP INDEX IF EXISTS idx_reports_severity_counts;
--   DROP INDEX IF EXISTS idx_reports_policy_ids;
--   DROP INDEX IF EXISTS idx_reports_policy_version;
--   DROP TRIGGER IF EXISTS trg_reports_update_severity_counts ON reports;
--   DROP FUNCTION IF EXISTS reports_update_severity_counts();
--   ALTER TABLE reports
--       DROP COLUMN IF EXISTS severity_counts,
--       DROP COLUMN IF EXISTS policy_id_distinct,
--       DROP COLUMN IF EXISTS policy_version;
-- COMMIT;
