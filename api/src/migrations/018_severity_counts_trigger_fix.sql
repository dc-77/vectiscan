-- ============================================================
-- Migration 018: severity_counts Trigger-Fix
-- ============================================================
-- Bug aus 016: Trigger las jsonb_array_elements(NEW.findings_data),
-- aber findings_data ist KEIN Array — es ist das vom Reporter gebaute
-- Objekt: {findings: [...], positive_findings: [...], severity_counts: {...},
-- recommendations: [...], overall_risk: ...}.
--
-- Daher zaehlte der Trigger immer 0 fuer alle Severities. Audit-Job 10285
-- hat das aufgedeckt: alle 6 Reports haben severity_counts = {0,0,0,0,0}.
--
-- Fix:
-- 1. Trigger-Funktion liest jetzt aus findings_data->'findings' (das echte
--    Findings-Array). Severity wird LOWER-Case verglichen — Reporter
--    schreibt UPPER ("HIGH"), aber Severity-Policy lower ("high").
-- 2. Backfill: alle bestehenden Reports einmal "anstossen" (UPDATE auf
--    findings_data triggert Re-Compute), damit severity_counts korrekt
--    gefuellt wird ohne Daten-Aenderung.
--
-- Idempotent: Trigger-Funktion wird CREATE OR REPLACE'd.
-- ============================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Trigger-Funktion neu definieren
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION reports_update_severity_counts() RETURNS TRIGGER AS $$
DECLARE
    findings_arr JSONB;
BEGIN
    -- Reporter schreibt findings_data als Objekt:
    --   {findings:[...], positive_findings:[...], severity_counts:{...}, ...}
    -- Wir wollen das innere findings-Array zaehlen.
    findings_arr := NEW.findings_data->'findings';

    IF findings_arr IS NULL OR jsonb_typeof(findings_arr) <> 'array' THEN
        NEW.severity_counts := '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'::JSONB;
    ELSE
        NEW.severity_counts := jsonb_build_object(
            'critical', (
                SELECT count(*)
                FROM jsonb_array_elements(findings_arr) f
                WHERE lower(f->>'severity') = 'critical'
            ),
            'high', (
                SELECT count(*)
                FROM jsonb_array_elements(findings_arr) f
                WHERE lower(f->>'severity') = 'high'
            ),
            'medium', (
                SELECT count(*)
                FROM jsonb_array_elements(findings_arr) f
                WHERE lower(f->>'severity') = 'medium'
            ),
            'low', (
                SELECT count(*)
                FROM jsonb_array_elements(findings_arr) f
                WHERE lower(f->>'severity') = 'low'
            ),
            'info', (
                SELECT count(*)
                FROM jsonb_array_elements(findings_arr) f
                WHERE lower(f->>'severity') = 'info'
            )
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- 2. Backfill: bestehende Reports neu durch den Trigger jagen.
--    Eine self-update ohne Wert-Aenderung triggert die BEFORE-UPDATE-Funktion
--    und re-berechnet severity_counts korrekt.
-- ----------------------------------------------------------------------------
UPDATE reports
   SET findings_data = findings_data
 WHERE findings_data IS NOT NULL;

COMMIT;

-- ============================================================
-- ROLLBACK (manuell, auskommentiert)
-- ============================================================
-- Es gibt keinen "echten" Rollback — die alte Trigger-Funktion war buggy.
-- Wer zurueck will, kopiert sich die Funktions-Definition aus
-- 016_severity_policy.sql und re-CREATE's. Backfill kann nicht zurueck-
-- gerollt werden (severity_counts ist abgeleitet, kein Verlust).
