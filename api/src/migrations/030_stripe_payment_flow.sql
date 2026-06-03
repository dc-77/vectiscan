-- ============================================================
-- Migration 030: Stripe Live Payment Flow (PA-1 / VEC-33)
-- ============================================================
-- Schliesst die Luecke, dass Subscriptions heute direkt mit
-- status='active' und amount_cents=0 erstellt werden — also ohne
-- jeglichen Zahlungsfluss (siehe routes/subscriptions.ts POST,
-- vor dieser Migration).
--
-- Neuer Flow:
--   POST /api/subscriptions  -> status='pending' + Stripe-Checkout-Session
--   Webhook checkout.session.completed (signaturverifiziert) -> 'active'
--   Abgebrochen/fehlgeschlagen                                -> 'payment_failed'
--
-- Idempotenz: jedes Stripe-Event wird genau einmal verarbeitet
-- (stripe_webhook_events, PK = Stripe-Event-ID evt_...). Doppelt
-- zugestellte Webhooks erzeugen keine Doppel-Aktivierung.
-- ============================================================

-- 1. Subscription: paid_at + Checkout-Session-ID + neuer Status 'payment_failed'
ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS stripe_checkout_session_id VARCHAR(255);

ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS chk_subscription_status;
ALTER TABLE subscriptions ADD CONSTRAINT chk_subscription_status
    CHECK (status IN ('pending', 'active', 'expired', 'cancelled', 'payment_failed'));

-- 2. Idempotenz-Ledger fuer Stripe-Webhooks
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    id              VARCHAR(255) PRIMARY KEY,   -- Stripe event.id (evt_...)
    type            VARCHAR(100) NOT NULL,
    subscription_id UUID REFERENCES subscriptions(id) ON DELETE SET NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_stripe_events_sub ON stripe_webhook_events(subscription_id);

-- ============================================================
-- Rollback
-- ============================================================
-- DROP TABLE IF EXISTS stripe_webhook_events;
-- ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS chk_subscription_status;
-- ALTER TABLE subscriptions ADD CONSTRAINT chk_subscription_status
--     CHECK (status IN ('pending','active','expired','cancelled'));
-- ALTER TABLE subscriptions DROP COLUMN IF EXISTS paid_at;
-- ALTER TABLE subscriptions DROP COLUMN IF EXISTS stripe_checkout_session_id;
