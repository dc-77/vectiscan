-- ============================================================
-- Migration 015: Performance-Metriken für Scan-Aufträge
-- ============================================================
-- Fügt eine JSONB-Spalte für strukturierte Performance-Metriken hinzu,
-- die der Scan-Worker am Ende jedes Scans füllt. Grundlage für
-- Admin-Dashboards und Kapazitätsplanung.
--
-- Gehört zum Plan: PERFORMANCE-PARALLELIZATION-PLAN.md
-- Struktur des JSONB siehe §10.1 im Plan.
-- ============================================================

-- ============================================================
-- 1. orders.performance_metrics JSONB
-- ============================================================
ALTER TABLE orders
    ADD COLUMN performance_metrics JSONB;

-- Kein NOT NULL und kein Default — bestehende Orders haben NULL, neue
-- Scans füllen das Feld. Das erlaubt uns, die Migration auch rückwirkend
-- ohne Daten-Backfill zu rollen.

-- Index nur, wenn wir später nach bestimmten Metriken filtern wollen.
-- Für einfaches Durchblättern reicht ein GIN-Index auf dem Top-Level:
CREATE INDEX idx_orders_performance_metrics
    ON orders USING GIN (performance_metrics);

-- ============================================================
-- 2. Beispiel-Query für das Admin-Dashboard
-- ============================================================
-- Durchschnittliche Scan-Dauer pro Paket, letzte 7 Tage:
--
-- SELECT
--     package,
--     COUNT(*) AS scan_count,
--     AVG((performance_metrics->'phase_durations_ms'->>'phase2_tier1')::int) / 1000
--         AS avg_tier1_seconds,
--     AVG((performance_metrics->>'zap_max_lease_wait_ms')::int)
--         AS avg_max_lease_wait_ms,
--     MAX((performance_metrics->>'zap_max_parallel_observed')::int)
--         AS max_parallelism_used
-- FROM orders
-- WHERE performance_metrics IS NOT NULL
--   AND finished_at > NOW() - INTERVAL '7 days'
-- GROUP BY package;

-- ============================================================
-- ROLLBACK (auskommentiert)
-- ============================================================
-- DROP INDEX IF EXISTS idx_orders_performance_metrics;
-- ALTER TABLE orders DROP COLUMN IF EXISTS performance_metrics;
