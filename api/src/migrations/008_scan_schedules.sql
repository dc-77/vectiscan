-- Recurring scan schedules
CREATE TABLE IF NOT EXISTS scan_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id     UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    target_url      VARCHAR(2048) NOT NULL,
    package         VARCHAR(20) NOT NULL DEFAULT 'professional',

    -- Schedule config
    schedule_type   VARCHAR(20) NOT NULL,  -- weekly, monthly, quarterly, once
    scheduled_at    TIMESTAMPTZ,           -- For 'once': fixed point in time

    -- State
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_scan_at    TIMESTAMPTZ,
    next_scan_at    TIMESTAMPTZ NOT NULL,
    last_order_id   UUID REFERENCES orders(id) ON DELETE SET NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_schedule_type CHECK (schedule_type IN ('weekly', 'monthly', 'quarterly', 'once')),
    CONSTRAINT chk_schedule_package CHECK (package IN ('basic', 'professional', 'nis2'))
);

CREATE INDEX IF NOT EXISTS idx_scan_schedules_next ON scan_schedules (next_scan_at) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_scan_schedules_customer ON scan_schedules (customer_id);
