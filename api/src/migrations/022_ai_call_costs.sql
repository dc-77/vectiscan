-- ============================================================
-- Migration 022: ai_call_costs Tabelle (PR-KI-Optim, 2026-05-03)
-- ============================================================
-- Persistiert pro Anthropic-API-Call (KI #1-4 + Reporter):
-- - Tokens (input/output/cache_creation/cache_read/thinking)
-- - Cost-USD (mit Prompt-Cache- und Thinking-Multipliern)
-- - Model + Cache-Hit-Status + Order/Subscription-Bezug
-- Ziel: Cost-Trends, Per-Subscription-Caps, Cache-Hit-Rate-Reporting.
-- ============================================================

CREATE TABLE IF NOT EXISTS ai_call_costs (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id                    UUID REFERENCES orders(id) ON DELETE SET NULL,
    subscription_id             UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
    -- 'ki1_host_strategy', 'ki2_tech_analysis', 'ki3_phase2_config',
    -- 'ki4_phase3', 'reporter_v1', 'status_report'
    ki_step                     VARCHAR(50) NOT NULL,
    model                       VARCHAR(100) NOT NULL,
    input_tokens                INTEGER NOT NULL DEFAULT 0,
    output_tokens               INTEGER NOT NULL DEFAULT 0,
    cache_creation_tokens       INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens           INTEGER NOT NULL DEFAULT 0,
    thinking_tokens             INTEGER NOT NULL DEFAULT 0,
    total_cost_usd              NUMERIC(10, 6) NOT NULL DEFAULT 0,
    cache_hit                   BOOLEAN NOT NULL DEFAULT FALSE,
    duration_ms                 INTEGER,
    batch_id                    VARCHAR(100),  -- bei M5 Batch-API
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_costs_order ON ai_call_costs(order_id);
CREATE INDEX IF NOT EXISTS idx_ai_costs_sub ON ai_call_costs(subscription_id);
CREATE INDEX IF NOT EXISTS idx_ai_costs_created ON ai_call_costs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_costs_step ON ai_call_costs(ki_step);

-- Optional: max_monthly_cost_usd Soft-Limit pro Subscription
ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS max_monthly_cost_usd NUMERIC(10, 2);

-- M5 (PR-KI-Optim 2026-05-03): Subscription-opt-in zur Batch-API
-- (50% Cost-Ersparnis bei +Latenz, max 24h). Default OFF.
ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS use_batch_api BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON TABLE ai_call_costs IS
    'PR-KI-Optim 2026-05-03: pro KI-Call Token+Cost-Audit fuer Cockpit + Caps.';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE subscriptions DROP COLUMN IF EXISTS max_monthly_cost_usd;
-- DROP TABLE IF EXISTS ai_call_costs;
