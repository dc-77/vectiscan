-- Migration 036: WebCheck-Free — Consent-Status `not_given` einführen (VEC-198, N1).
--
-- Befund (Sven-QA auf VEC-173, N1 / Greta-Entscheidung): Ein nie eingewilligter
-- Lead (Opt-in-Box leer) wurde bisher als `consent_status='declined'` modelliert.
-- `declined` impliziert eine AKTIVE Ablehnung; eine ungesetzte Opt-in-Box ist aber
-- „nie eingewilligt", nicht „abgelehnt". Das verfälscht Reporting (aufgeblähte
-- Declined-Rate), Suppression-Hygiene (vgl. VEC-188) und die künftige
-- Re-Permission-Logik (ein Nie-Eingewilligter darf mit frischer Rechtsgrundlage
-- erneut angesprochen werden; ein aktiv Ablehnender konservativer).
--
-- Diese Migration erweitert ausschliesslich die erlaubten CHECK-Werte um
-- `not_given`. Semantik:
--   not_given  — Opt-in-Box leer, nie eingewilligt (legal_basis 'none')   [NEU]
--   pending    — DOI-Mail versandt, Bestaetigung ausstehend                (unveraendert)
--   confirmed  — DOI bestaetigt, Marketing-Verarbeitung zulaessig          (unveraendert)
--   declined   — aktive Negativ-Aktion (DOI nicht in Frist / Opt-out)       (jetzt reserviert)
--   withdrawn  — nachtraeglicher Widerruf                                   (unveraendert)
--
-- Verhalten unveraendert: ohne `confirmed` keine Marketing-Verarbeitung. Der
-- Art.-7-Nachweis bleibt der boolesche `marketing_consent` (VEC-173 / Migr. 035).
--
-- Idempotent (DROP CONSTRAINT IF EXISTS vor ADD) und rueckwaertskompatibel:
-- additiv, kein bestehender Wert wird ungueltig. Rollback = CHECK ohne 'not_given'
-- neu setzen (nur moeglich, solange keine Zeile 'not_given' fuehrt).
--
-- Den bestehenden consent_status-CHECK namensunabhaengig entfernen: die Spalten-
-- CHECK aus Migration 032 war unbenannt (Postgres-Default <tabelle>_<spalte>_check),
-- aber ein hartkodierter DROP ... IF EXISTS wuerde bei abweichendem Auto-Namen
-- still no-oppen und den alten restriktiven CHECK aktiv lassen -> 'not_given'-
-- Inserts braechen zur Laufzeit. Daher jeden CHECK auf consent_status per Katalog
-- aufloesen (idempotent, race-sicher).
DO $$
DECLARE
  c record;
BEGIN
  FOR c IN
    SELECT con.conname
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    WHERE rel.relname = 'webcheck_leads'
      AND con.contype = 'c'
      AND pg_get_constraintdef(con.oid) ILIKE '%consent_status%'
  LOOP
    EXECUTE format('ALTER TABLE webcheck_leads DROP CONSTRAINT %I', c.conname);
  END LOOP;
END
$$;

ALTER TABLE webcheck_leads
  ADD CONSTRAINT webcheck_leads_consent_status_check
  CHECK (consent_status IN ('not_given', 'pending', 'confirmed', 'declined', 'withdrawn'));
