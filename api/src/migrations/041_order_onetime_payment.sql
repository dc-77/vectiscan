-- ============================================================
-- Migration 041: Stripe Einzelscan-Checkout (mode=payment) — VEC-436
-- ============================================================
-- Schliesst den Gratis-Leak: ein kostenpflichtiger Einzelscan
-- (Perimeter) lief bisher ohne Zahlung. Neuer Flow analog zum Abo,
-- aber als Einmalzahlung:
--
--   POST /api/orders (kostenpflichtiges Paket, kein aktives Abo)
--     -> orders.status='awaiting_payment', payment_status='unpaid'
--     -> Stripe Checkout Session mode=payment (metadata.order_id)
--   Webhook checkout.session.completed (signaturverifiziert, paid)
--     -> payment_status='paid', status='precheck_running' + Precheck-Enqueue
--   Abgebrochen/abgelaufen/fehlgeschlagen
--     -> payment_status='failed' (kein Scan)
--
-- Idempotenz: jedes Stripe-Event genau einmal (stripe_webhook_events,
-- PK = evt_...). Der atomare Enqueue-Claim nutzt scan_targets.
-- precheck_enqueued_at (Migration 031) — identisch zum Abo-Pfad.
-- ============================================================

-- 1. Orders: Einzelzahlungs-Felder (Legacy-Spalten stripe_payment_id/
--    stripe_checkout_id/paid_at/amount_cents/currency existieren bereits
--    aus 003_mvp_schema; wir ergaenzen die Abo-konforme Session-ID + den
--    expliziten Zahlungsstatus).
ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS payment_status VARCHAR(20),
    ADD COLUMN IF NOT EXISTS stripe_checkout_session_id VARCHAR(255);

-- payment_status NULL = kein Zahlungsfluss noetig (Gratis-Paket / aktives Abo).
ALTER TABLE orders DROP CONSTRAINT IF EXISTS chk_orders_payment_status;
ALTER TABLE orders ADD CONSTRAINT chk_orders_payment_status
    CHECK (payment_status IS NULL
        OR payment_status IN ('unpaid', 'paid', 'failed', 'expired'));

-- 2. Idempotenz-Ledger um order_id erweitern (one-time-Orders werden ueber
--    die Order-Metadaten statt subscription_id aufgeloest).
ALTER TABLE stripe_webhook_events
    ADD COLUMN IF NOT EXISTS order_id UUID REFERENCES orders(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_stripe_events_order ON stripe_webhook_events(order_id);

-- ============================================================
-- Rollback
-- ============================================================
-- DROP INDEX IF EXISTS idx_stripe_events_order;
-- ALTER TABLE stripe_webhook_events DROP COLUMN IF EXISTS order_id;
-- ALTER TABLE orders DROP CONSTRAINT IF EXISTS chk_orders_payment_status;
-- ALTER TABLE orders DROP COLUMN IF EXISTS stripe_checkout_session_id;
-- ALTER TABLE orders DROP COLUMN IF EXISTS payment_status;
