-- ============================================================
-- Migration 026: Shodan on-demand Pre-Warm (F-P0A-006, 2026-05-07)
-- ============================================================
-- Erweitert das Schema um zwei Felder, damit der scan-worker beim
-- Scan-Start einen Shodan on-demand Scan ausloesen kann
-- (POST /shodan/scan). Frischere Shodan-Daten werden 24-48h spaeter in
-- Phase 0a sichtbar; nutzt das Freelancer-Plan Scan-Credit-Pool
-- (~5000/mo, getrennt vom Query-Pool).
--
-- Subscription-Pfad: default-on. Trigger laeuft fuer jede Subscription-
-- Order automatisch beim Scan-Start.
--
-- One-Off-Order-Pfad: opt-in. Customer aktiviert in der Order-Form den
-- Toggle "Shodan Pre-Warm aktivieren"; Backend persistiert das in
-- `orders.pre_warm_requested`. Admin-Approval sollte erst nach 24-48h
-- erteilt werden, damit die Pre-Warm-Daten verfuegbar sind.
--
-- Rechtliche Mitigation: Pre-Warm wird im scan-worker nach dem
-- Release-Punkt (Status `queued`, scan_authorizations bereits
-- hochgeladen) ausgeloest — nicht direkt nach Pre-Check.
--
-- Persistenz dient als Audit-Trail fuer Forensik und spaeteres Status-
-- Polling der Shodan-Scan-IDs.
-- ============================================================

-- Subscription-Pfad: shodan_scan_request als JSONB
-- Format: { "scan_id": "...", "requested_at": "ISO-8601",
--           "ips": ["1.2.3.4", ...], "status": "submitted" }
ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS shodan_scan_request JSONB DEFAULT NULL;

COMMENT ON COLUMN subscriptions.shodan_scan_request IS
    'F-P0A-006: Letzter Shodan on-demand Scan-Request (scan_id, ips, requested_at, status). NULL = noch kein Pre-Warm.';

-- One-Off-Order-Pfad: pre_warm_requested als BOOLEAN
ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS pre_warm_requested BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN orders.pre_warm_requested IS
    'F-P0A-006: Customer hat Shodan Pre-Warm bei Order-Anlage opt-in aktiviert (One-Off-Pfad).';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE subscriptions DROP COLUMN IF EXISTS shodan_scan_request;
-- ALTER TABLE orders DROP COLUMN IF EXISTS pre_warm_requested;
