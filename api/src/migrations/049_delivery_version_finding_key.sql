-- ============================================================
-- Migration 049: Auslieferungsversion und stabiler Befundschluessel (S6b-2)
-- ============================================================
-- S6b-2 (Sep 2026), Entscheidung DC 23.09.: Das Deckblatt zeigt die
-- Auslieferungsversion (1 bei der ersten Freigabe, danach je Freigabe
-- hochgezaehlt); die Erzeugungsnummer reports.version steht nur noch am
-- Ende der Fusszeile. Der report-worker setzt delivery_version nur fuer
-- Zeilen aus einer Freigabe (approved), sonst bleibt sie NULL.
--
-- Issue #28: Befund-Ausschluesse wirken im Katalogweg ueber einen
-- stabilen Schluessel <Regel oder Buendel>/<Gruppe>/<Zustaendigkeit>
-- statt ueber die Befundnummer; die verbleibenden Befunde behalten ihre
-- Nummer. finding_key haelt den Schluessel neben der Nummer, die die
-- Admin-Oberflaeche weiter anzeigt.
--
-- BEWUSST additiv + nullable: KEIN NOT NULL, KEIN UNIQUE, KEIN Backfill
-- (Rolling-Deploy-Regel wie Migration 044 bis 047).
-- ============================================================

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS delivery_version INTEGER DEFAULT NULL;

COMMENT ON COLUMN reports.delivery_version IS
    'S6b-2 (Sep 2026): Auslieferungsversion auf dem Deckblatt, 1 bei der ersten Freigabe, danach je Freigabe hochgezaehlt. NULL fuer Entwuerfe (pending_review) und Zeilen vor Migration 049.';

ALTER TABLE finding_exclusions
    ADD COLUMN IF NOT EXISTS finding_key TEXT DEFAULT NULL;

COMMENT ON COLUMN finding_exclusions.finding_key IS
    'S6b-2 (Issue #28): stabiler Schluessel des ausgeschlossenen Sachverhalts aus reports.findings_data (findings[].key). NULL fuer Ausschluesse vor Migration 049; der report-worker bildet sie ueber die Befundnummer ab.';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE reports DROP COLUMN IF EXISTS delivery_version;
-- ALTER TABLE finding_exclusions DROP COLUMN IF EXISTS finding_key;
