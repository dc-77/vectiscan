-- ============================================================================
-- Migration 015: Threat-Intel-Snapshots-Tabelle
-- ============================================================================
-- Spec: docs/specs/2026-Q2-determinism/05-schema-migrations.md
--
-- Legt das Schema für Threat-Intel-Snapshots an. In diesem Q2-Block wird
-- die Tabelle nur erstellt, aber NOCH NICHT aktiv beschrieben. Die aktive
-- Nutzung (Snapshot pro Scan, Reproducibility-Garantie) folgt in P2.
--
-- Idempotent: re-run-safe via IF NOT EXISTS.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. Tabelle erstellen
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_intel_snapshots (
    snapshot_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Versions-Tags (z.B. NVD-Mod-Date, KEV-Catalog-Version)
    nvd_version     TEXT,
    kev_version     TEXT,
    epss_version    TEXT,

    -- Snapshot-Daten als JSONB (komprimiert via TOAST)
    -- Pro Quelle ein Objekt mit den Records, die zum Snapshot-Zeitpunkt aktuell waren.
    nvd_data        JSONB,
    kev_data        JSONB,
    epss_data       JSONB,

    -- Erweiterbar: counts, source_urls, hashes, etc.
    metadata        JSONB DEFAULT '{}'::JSONB
);

COMMENT ON TABLE threat_intel_snapshots IS
    'Snapshot der Threat-Intel-Daten zum Zeitpunkt eines Scans. Ermöglicht '
    'reproduzierbare Re-Scans und Audit-Trail bei sich ändernden NVD/KEV/EPSS-Daten. '
    'Aktiv genutzt ab P2 (Q3/2026).';

-- ----------------------------------------------------------------------------
-- 2. Index für Snapshot-Lookup
-- ----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_ti_snapshots_created_at
    ON threat_intel_snapshots(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ti_snapshots_nvd_version
    ON threat_intel_snapshots(nvd_version);

CREATE INDEX IF NOT EXISTS idx_ti_snapshots_kev_version
    ON threat_intel_snapshots(kev_version);

-- ----------------------------------------------------------------------------
-- 3. Foreign Key auf orders
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'orders'
        AND column_name = 'threat_intel_snapshot_id'
    ) THEN
        ALTER TABLE orders
            ADD COLUMN threat_intel_snapshot_id UUID
            REFERENCES threat_intel_snapshots(snapshot_id)
            ON DELETE SET NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_orders_ti_snapshot
    ON orders(threat_intel_snapshot_id);

-- ----------------------------------------------------------------------------
-- 4. Migrations-Eintrag
-- ----------------------------------------------------------------------------
INSERT INTO migrations (version, applied_at)
VALUES (15, NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;

-- ============================================================================
-- Rollback (manuell ausführen falls nötig)
-- ============================================================================
-- BEGIN;
--   ALTER TABLE orders DROP COLUMN IF EXISTS threat_intel_snapshot_id;
--   DROP INDEX IF EXISTS idx_orders_ti_snapshot;
--   DROP INDEX IF EXISTS idx_ti_snapshots_created_at;
--   DROP INDEX IF EXISTS idx_ti_snapshots_nvd_version;
--   DROP INDEX IF EXISTS idx_ti_snapshots_kev_version;
--   DROP TABLE IF EXISTS threat_intel_snapshots;
--   DELETE FROM migrations WHERE version = 15;
-- COMMIT;
