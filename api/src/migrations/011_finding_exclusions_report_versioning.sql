-- Migration 011: Finding exclusions + report versioning
-- Adds manual false-positive management and PDF report versioning.

-- 1. finding_exclusions table — manual FP marking
CREATE TABLE IF NOT EXISTS finding_exclusions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id        UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    finding_id      VARCHAR(20) NOT NULL,
    excluded_by     UUID NOT NULL REFERENCES users(id),
    reason          TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exclusions_order_finding
    ON finding_exclusions(order_id, finding_id);

-- 2. reports versioning columns
ALTER TABLE reports ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS superseded_by UUID REFERENCES reports(id);
ALTER TABLE reports ADD COLUMN IF NOT EXISTS excluded_findings JSONB DEFAULT '[]'::jsonb;

-- 3. Index for fast latest-version lookup
CREATE INDEX IF NOT EXISTS idx_reports_order_version
    ON reports(order_id, version DESC);

-- 4. Remove UNIQUE constraint on reports.order_id (allows multiple versions)
-- Only drop if it exists — idempotent
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'reports_order_id_key'
    ) THEN
        ALTER TABLE reports DROP CONSTRAINT reports_order_id_key;
    END IF;
END $$;
