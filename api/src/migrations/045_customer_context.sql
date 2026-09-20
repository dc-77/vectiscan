-- ============================================================
-- Migration 045: Kundenkontext auf orders (S5)
-- ============================================================
-- S5 (Sep 2026): Der v3-Bericht nennt den Auftraggeber bisher nur
-- "Auftraggeber", weil weder Job-Payload noch report_mapper einen
-- Kundennamen fuehren. reporter/v3/build_report_data erwartet ihn in
-- orders.customer_context; diese Spalte legt ihn an.
--
-- Form (flache Werte plus Herkunft je Feld):
--   {
--     "firmenname": "Beispiel GmbH",
--     "kuerzel":    "BSP",
--     "branche":    "Maschinenbau",
--     "mitarbeiter":"120",
--     "systeme":    [{"fqdn": "www.beispiel.de", "zweck": "Unternehmenswebsite"}],
--     "sources": {
--       "firmenname": {"source": "kunde"},
--       "branche":    {"source": "recherche", "url": "https://..."},
--       "systeme":    {"source": "admin"}
--     }
--   }
--
-- source je Feld ist 'kunde' (Angabe im Bestellprozess), 'recherche'
-- (Vorschlag der Recherche-KI, immer mit Fundstellen-URL) oder 'admin'
-- (im Admin-Review nachgetragen). Ein Vorschlag ueberschreibt nie eine
-- Kundenangabe oder eine Admin-Korrektur.
--
-- Die Werte liegen bewusst flach neben "sources", damit die vorhandenen
-- Leser (reporter/v3/report_data.py context.get("kuerzel")) unveraendert
-- funktionieren.
--
-- BEWUSST additiv + nullable: KEIN NOT NULL, KEIN CHECK und KEIN Backfill.
-- Waehrend des Rolling-Deploys laufen alte api- und report-worker-Images
-- weiter, die die Spalte nicht kennen.
-- ============================================================

ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS customer_context JSONB DEFAULT NULL;

COMMENT ON COLUMN orders.customer_context IS
    'S5 (Sep 2026): Optionaler Kundenkontext fuer den Bericht. Flache Felder firmenname, kuerzel, branche, mitarbeiter, systeme[{fqdn, zweck}] plus sources{feld: {source, url}} mit source in kunde, recherche, admin. NULL wenn nichts bekannt ist; der Bericht bleibt dann generisch.';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE orders DROP COLUMN IF EXISTS customer_context;
