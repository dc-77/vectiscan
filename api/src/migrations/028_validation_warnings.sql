-- ============================================================
-- Migration 028: Validation-Gate-Warnings auf reports (M1)
-- ============================================================
-- M1 (Q2/2026 Report-Redesign): Der report-worker laeuft pro Job durch eine
-- Validation-Gate (Phase A in docs/report-erstellung/01_Fehleranalyse_und_
-- Korrekturplan.md). In WARN-Mode werden Defekte hier persistiert; in
-- STRICT-Mode blockiert die Gate den Build und der Inhalt landet im
-- order.error_message.
--
-- Format (1:1 aus ValidationResult.to_json()):
-- {
--   "passed": true|false,
--   "level": "warn"|"strict"|"off",
--   "errors": [{"check": "titles", "severity": "error",
--               "finding_id": "VS-2026-001", "message": "...",
--               "detail": { ... }}, ...],
--   "warnings": [ ... gleiche Struktur ],
--   "checks_run": ["titles", "ids", "cvss", ...],
--   "checks_skipped": [],
--   "error_count": 12,
--   "warning_count": 3
-- }
-- ============================================================

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS validation_warnings JSONB DEFAULT NULL;

COMMENT ON COLUMN reports.validation_warnings IS
    'M1 (Q2/2026): Output der ValidationGate vor PDF-Generation. Im WARN-Mode geloggt, im STRICT-Mode blockiert die Gate und Inhalt steht im orders.error_message. Format: ValidationResult.to_json().';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE reports DROP COLUMN IF EXISTS validation_warnings;
