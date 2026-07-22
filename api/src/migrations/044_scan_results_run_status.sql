-- ============================================================
-- Migration 044: Tool-Lauf-Status auf scan_results (A7)
-- ============================================================
-- A7 (Phase 1, Jul 2026): Jeder Tool-Lauf schreibt genau eine
-- Ergebniszeile — auch wenn das Tool gar nicht lief. Bisher liess sich
-- "nicht gelaufen" nicht von "gelaufen und leer" unterscheiden, weil nur
-- exit_code existierte und ausgelassene Tools ueberhaupt keine Zeile
-- erzeugten.
--
-- Vokabular status:
--   'ok'      — Tool lief, Exit-Code liegt in TOOL_OK_EXIT_CODES
--   'failed'  — Tool lief und schlug fehl (oder Exception im Runner)
--   'skipped' — Tool wurde bewusst nicht ausgefuehrt (Paket-Gating,
--               KI-Skip, fehlender API-Key, Host nicht erreichbar ...)
--   'timeout' — Tool lief in den Timeout (exit_code -1)
--   'blocked' — Lauf durch WAF/Block-Detection abgebrochen, Retry via VPN
--   NULL      — Legacy-Zeile aus der Zeit vor A7. Konsumenten leiten den
--               Status dann wie bisher aus exit_code ab.
--
-- skip_reason traegt die maschinenlesbare Kurzbegruendung
-- (z.B. 'not_in_package', 'no_api_key', 'zap_daemon_unavailable').
--
-- BEWUSST additiv + nullable: KEIN NOT NULL, KEIN CHECK-Constraint und
-- KEIN Backfill. Waehrend des Rolling-Deploys laufen alte scan-worker-
-- Images weiter, die die neuen Spalten nicht befuellen — ein NOT NULL
-- oder CHECK wuerde deren INSERTs sofort abweisen.
-- ============================================================

ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS status VARCHAR(16) DEFAULT NULL;

ALTER TABLE scan_results
    ADD COLUMN IF NOT EXISTS skip_reason VARCHAR(160) DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_scan_results_order_status
    ON scan_results (order_id, status);

COMMENT ON COLUMN scan_results.status IS
    'A7 (Jul 2026): Lauf-Status eines Tools. Vokabular: ok, failed, skipped, timeout, blocked. NULL = Legacy-Zeile vor A7, Konsument leitet den Status aus exit_code ab.';

COMMENT ON COLUMN scan_results.skip_reason IS
    'A7 (Jul 2026): Kurzbegruendung fuer status != ok, z.B. not_in_package, no_api_key, zap_daemon_unavailable, host_unreachable. NULL wenn nicht protokolliert.';

-- ============================================================
-- Rollback
-- ============================================================
-- DROP INDEX IF EXISTS idx_scan_results_order_status;
-- ALTER TABLE scan_results DROP COLUMN IF EXISTS skip_reason;
-- ALTER TABLE scan_results DROP COLUMN IF EXISTS status;
