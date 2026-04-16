-- Migration 012: Subscriptions + Admin-Review-Workflow
-- Adds subscription management tables and review workflow statuses.

-- 1. subscriptions table — yearly subscription plans
CREATE TABLE IF NOT EXISTS subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id             UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    package                 VARCHAR(30) NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'pending',
    stripe_subscription_id  VARCHAR(255),
    stripe_price_id         VARCHAR(255),
    amount_cents            INTEGER NOT NULL DEFAULT 0,
    currency                VARCHAR(3) NOT NULL DEFAULT 'EUR',
    started_at              TIMESTAMPTZ,
    expires_at              TIMESTAMPTZ,
    scan_interval           VARCHAR(20) NOT NULL DEFAULT 'monthly',
    max_domains             INTEGER NOT NULL DEFAULT 5,
    max_rescans             INTEGER NOT NULL DEFAULT 3,
    rescans_used            INTEGER NOT NULL DEFAULT 0,
    report_emails           TEXT[] NOT NULL DEFAULT '{}',
    last_scan_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_subscription_status
        CHECK (status IN ('pending', 'active', 'expired', 'cancelled')),
    CONSTRAINT chk_subscription_package
        CHECK (package IN ('perimeter', 'insurance', 'compliance', 'supplychain', 'webcheck')),
    CONSTRAINT chk_subscription_interval
        CHECK (scan_interval IN ('weekly', 'monthly', 'quarterly'))
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(customer_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);

-- 2. subscription_domains table — domains per subscription
CREATE TABLE IF NOT EXISTS subscription_domains (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id         UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    domain                  VARCHAR(255) NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'pending_approval',
    verified_at             TIMESTAMPTZ,
    verification_method     VARCHAR(20),
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_subscription_domain UNIQUE (subscription_id, domain),
    CONSTRAINT chk_subdomain_status
        CHECK (status IN ('pending_approval', 'approved', 'rejected', 'verified'))
);

-- 3. Add subscription_id to orders (link orders to subscriptions)
ALTER TABLE orders ADD COLUMN IF NOT EXISTS subscription_id UUID REFERENCES subscriptions(id);
ALTER TABLE orders ADD COLUMN IF NOT EXISTS is_rescan BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(id);
ALTER TABLE orders ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS review_notes TEXT;

-- 4. Add new order statuses to the existing status flow
-- Current: verification_pending → queued → scanning → ... → scan_complete → report_generating → report_complete
-- New:     ... → scan_complete → pending_review → approved → report_generating → report_complete → delivered
-- (No CHECK constraint on status exists, so we just use the new values)

CREATE INDEX IF NOT EXISTS idx_orders_subscription ON orders(subscription_id);
CREATE INDEX IF NOT EXISTS idx_orders_status_review ON orders(status) WHERE status = 'pending_review';
