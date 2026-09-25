-- ============================================================
-- Migration 048: Kurzname im Kundenkontext (S6b-1)
-- ============================================================
-- S6b-1 (Sep 2026, spec/09 Q15): Der Kurzname steht in Fusszeile und
-- PDF-Titel. Bisher wurde er aus dem Firmennamen abgeleitet und las sich
-- falsch ("Huendgen Entsorgungs", "Josef Heuel", "Junkerwerk Linder GmbH
-- + Co."). Er ist jetzt ein eigenes Feld "kurzname" im Kundenkontext,
-- mit Herkunft wie die uebrigen Felder (kunde, recherche, admin).
--
-- orders.customer_context ist JSONB mit flachen Feldern (Migration 045);
-- ein weiteres Feld braucht keine neue Spalte. Diese Migration fuehrt nur
-- die dokumentierte Form im Spaltenkommentar nach. COMMENT ON ist
-- idempotent; initDb wendet sie nur an, solange der Kommentar "kurzname"
-- noch nicht nennt.
--
-- BEWUSST ohne DDL an Daten: KEIN Backfill, KEIN UPDATE (Rolling-Deploy-
-- Regel wie Migration 044 bis 047). Fehlt der Kurzname, leitet der
-- report-worker ihn weiter aus dem Firmennamen ab.
-- ============================================================

COMMENT ON COLUMN orders.customer_context IS
    'S5/S6b-1 (Sep 2026): Optionaler Kundenkontext fuer den Bericht. Flache Felder firmenname, kurzname, kuerzel, branche, mitarbeiter, systeme[{fqdn, zweck}] plus sources{feld: {source, url}} mit source in kunde, recherche, admin. kurzname steht in Fusszeile und PDF-Titel. NULL wenn nichts bekannt ist; der Bericht bleibt dann generisch.';

-- ============================================================
-- Rollback
-- ============================================================
-- COMMENT ON COLUMN orders.customer_context IS
--     'S5 (Sep 2026): Optionaler Kundenkontext fuer den Bericht. Flache Felder firmenname, kuerzel, branche, mitarbeiter, systeme[{fqdn, zweck}] plus sources{feld: {source, url}} mit source in kunde, recherche, admin. NULL wenn nichts bekannt ist; der Bericht bleibt dann generisch.';
