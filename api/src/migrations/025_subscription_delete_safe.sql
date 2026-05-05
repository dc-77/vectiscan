-- ============================================================
-- Migration 025: orders.subscription_id ON DELETE SET NULL (2026-05-05)
-- ============================================================
-- Admin-Endpoint DELETE /api/admin/subscriptions/:id loescht Subs.
-- Heute hat orders.subscription_id KEIN ON-DELETE-Verhalten → DELETE
-- schlaegt mit FK-Constraint fehl wenn Orders existieren.
--
-- Loesung: SET NULL. Orders + Reports + Findings bleiben erhalten
-- (Audit-Trail, Compliance), aber Sub-Bezug wird genullt.
-- CASCADE wuerde auch Reports loeschen — zu destruktiv fuer Default.
-- ============================================================

ALTER TABLE orders
    DROP CONSTRAINT IF EXISTS orders_subscription_id_fkey;

ALTER TABLE orders
    ADD CONSTRAINT orders_subscription_id_fkey
    FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
    ON DELETE SET NULL;
