-- Migration 009: VectiScan v2 — Package expansion (3 → 5) + new columns + threat_intel_cache
-- Migrates: basic→webcheck, professional→perimeter, nis2→compliance

BEGIN;

-- Step 1: Migrate existing data to new package names
UPDATE orders SET package = 'webcheck' WHERE package = 'basic';
UPDATE orders SET package = 'perimeter' WHERE package = 'professional';
UPDATE orders SET package = 'compliance' WHERE package = 'nis2';

UPDATE scan_schedules SET package = 'webcheck' WHERE package = 'basic';
UPDATE scan_schedules SET package = 'perimeter' WHERE package = 'professional';
UPDATE scan_schedules SET package = 'compliance' WHERE package = 'nis2';

-- Step 2: Update CHECK constraints to 5 packages
ALTER TABLE orders DROP CONSTRAINT IF EXISTS chk_orders_package;
ALTER TABLE orders ADD CONSTRAINT chk_orders_package
    CHECK (package IN ('webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance'));

ALTER TABLE scan_schedules DROP CONSTRAINT IF EXISTS chk_schedule_package;
ALTER TABLE scan_schedules ADD CONSTRAINT chk_schedule_package
    CHECK (package IN ('webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance'));

-- Step 3: New columns on orders for Phase 0a / Phase 3 data
ALTER TABLE orders ADD COLUMN IF NOT EXISTS passive_intel_summary JSONB;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS correlation_data JSONB;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS business_impact_score DECIMAL(3,1);

-- Step 4: Threat Intelligence cache table
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cache_key   VARCHAR(255) NOT NULL UNIQUE,
    cache_value JSONB NOT NULL,
    source      VARCHAR(50) NOT NULL,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_cache_key ON threat_intel_cache(cache_key);
CREATE INDEX IF NOT EXISTS idx_threat_intel_cache_expires ON threat_intel_cache(expires_at);

COMMIT;
