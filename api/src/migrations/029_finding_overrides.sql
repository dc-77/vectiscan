-- ============================================================
-- Migration 029: Admin-Overrides pro Finding
-- ============================================================
-- Hintergrund (heuel.com + securess.de, Mai 2026): Der Validation-Gate
-- meldet warnings wie "CVSS-Score weicht von Vektor-berechnetem Score ab"
-- oder "Title nennt FTP, Body beschreibt SFTP". Der Admin soll diese im
-- UI pro Finding korrigieren oder als geprueft markieren koennen, ohne
-- den Claude-Output umzuschreiben.
--
-- Ein Override kann:
--   1. ein Feld am Finding ueberschreiben (z.B. cvss_score=7.3 statt 7.5)
--   2. das Finding als geprueft/akzeptiert markieren (ignored=true) —
--      Warnings dazu werden im UI ausgeblendet, Finding bleibt im Report
--   3. das Finding komplett vom Report ausschliessen (kommt aus der
--      existierenden finding_exclusions-Tabelle, hier nicht doppelt)
--
-- Mehrere Overrides pro Finding moeglich (z.B. cvss_score + severity).
-- Eindeutigkeit: (order_id, finding_id, field_name).
-- ============================================================

CREATE TABLE IF NOT EXISTS finding_overrides (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id    UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    finding_id  TEXT NOT NULL,
    field_name  TEXT NOT NULL,  -- z.B. 'cvss_score', 'severity', 'title', '_ignored'
    new_value   JSONB NOT NULL, -- {"value": 7.3} oder {"value": "MEDIUM"} oder {"value": true}
    note        TEXT,           -- optionaler Admin-Kommentar
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (order_id, finding_id, field_name)
);

CREATE INDEX IF NOT EXISTS idx_finding_overrides_order
    ON finding_overrides (order_id);

COMMENT ON TABLE finding_overrides IS
    'Mai 2026: Admin-seitige Overrides auf einzelnen Findings. Wird vom report-worker vor Validation-Gate und vor PDF-Render appliziert.';
COMMENT ON COLUMN finding_overrides.field_name IS
    'Spezial-Feld "_ignored": markiert Finding als "warnings akzeptiert" (kein Render-Effekt, nur UI).';
COMMENT ON COLUMN finding_overrides.new_value IS
    'JSONB-Objekt mit Schluessel "value". JSONB statt TEXT damit numerische Werte (cvss_score) typstabil bleiben.';

-- ============================================================
-- Rollback
-- ============================================================
-- DROP TABLE IF EXISTS finding_overrides;
