-- ============================================================
-- Migration 024: Determinismus-KPI fuer subscription_posture (2026-05-04)
-- ============================================================
-- Misst die Reproduzierbarkeit von Reports ueber wiederholte Scans:
-- determinism_score = |intersection(policy_ids letzten 3 Scans)|
--                   / |union(policy_ids letzten 3 Scans)| * 100
--
-- Wert 100 = perfekt deterministisch (jeder Scan findet exakt die gleichen
-- Policy-IDs). Wert <70 = Drift-Indikator → Hinweis im Report.
-- ============================================================

ALTER TABLE subscription_posture
    ADD COLUMN IF NOT EXISTS determinism_score NUMERIC(5,2),
    ADD COLUMN IF NOT EXISTS determinism_sample_size INTEGER DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_subscription_posture_determinism
    ON subscription_posture(determinism_score)
    WHERE determinism_score IS NOT NULL;
