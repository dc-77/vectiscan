-- ============================================================
-- Migration 047: Berichtsnummer in reports (S6a)
-- ============================================================
-- S6a (Sep 2026): Die Berichtsnummer vom Deckblatt war nur je
-- Kundenkuerzel und Scantag eindeutig; ohne Kuerzel trugen Huendgen und
-- castenow beide VS-2026-0917. Neu: VS-<Jahr>-<MMTT>-<erste vier Zeichen
-- der Order-ID>, stabil ueber alle Versionen desselben Auftrags. Sie
-- steht auf Deckblatt, in der Fusszeile und hier.
--
-- Gesetzt nur im Katalogweg (report-worker, v3); Zeilen aus dem
-- Legacy-Weg und alle Zeilen vor dieser Migration bleiben NULL.
--
-- BEWUSST additiv + nullable: KEIN NOT NULL, KEIN UNIQUE (jede Version
-- desselben Auftrags traegt dieselbe Nummer), KEIN Backfill
-- (Rolling-Deploy-Regel wie Migration 044).
-- ============================================================

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS report_number VARCHAR(40) DEFAULT NULL;

COMMENT ON COLUMN reports.report_number IS
    'S6a (Sep 2026): Berichtsnummer VS-<Jahr>-<MMTT>-<Order[:4]> wie auf Deckblatt und Fusszeile. Gleich fuer alle Versionen eines Auftrags. NULL fuer Legacy-Berichte und Zeilen vor Migration 047.';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE reports DROP COLUMN IF EXISTS report_number;
