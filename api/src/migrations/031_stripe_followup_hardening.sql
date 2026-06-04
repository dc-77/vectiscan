-- ============================================================
-- Migration 031: Stripe-Zahlungsfluss Follow-up-Haertung (VEC-112)
-- ============================================================
-- Folge-Ticket aus dem Security-Review VEC-102. Adressiert die
-- Lower-Severity-Befunde L1/I2 (L2/I3 sind reine Code-Aenderungen
-- ohne Schema-Bezug).
--
-- L1 (Aktivierungs-Atomicitaet): Bisher war die Abo-Aktivierung und
-- das Freischalten des Scan-Kontingents (enqueuePrecheck) nicht atomar
-- und das Enqueue haengte am Sub-Status. Brach Schritt 2 ab, wurde der
-- Idempotenz-Claim zurueckgenommen, beim Stripe-Retry war das Abo aber
-- schon 'active' -> der Aktivierungs-UPDATE matchte 0 Zeilen -> frueher
-- Return -> Precheck wurde NIE enqueued (bezahlt, aber kein Scan).
--
-- Fix-Baustein hier: ein idempotenter Claim-Marker pro Target. Das
-- Enqueue wird nun atomar an `scan_targets.precheck_enqueued_at IS NULL`
-- gekoppelt (statt am Abo-Status). Ein erneuter Lauf beansprucht nur
-- noch nicht-enqueued Targets; bereits beanspruchte matchen 0 Zeilen.
-- Der Marker ist bewusst eine eigene Spalte (kein neuer Status), damit
-- die scan_targets-Statusmaschine und der precheck-worker unberuehrt
-- bleiben.
-- ============================================================

-- 1. L1: idempotenter Enqueue-Claim-Marker auf scan_targets.
ALTER TABLE scan_targets
    ADD COLUMN IF NOT EXISTS precheck_enqueued_at TIMESTAMPTZ;

-- Partieller Index fuer die Claim-Query (nur noch nicht-enqueued
-- Subscription-Targets). Klein, da pro Abo nur wenige Targets offen.
CREATE INDEX IF NOT EXISTS idx_scan_targets_precheck_unqueued
    ON scan_targets(subscription_id)
    WHERE status = 'pending_precheck' AND precheck_enqueued_at IS NULL;

-- ============================================================
-- Rollback
-- ============================================================
-- DROP INDEX IF EXISTS idx_scan_targets_precheck_unqueued;
-- ALTER TABLE scan_targets DROP COLUMN IF EXISTS precheck_enqueued_at;
