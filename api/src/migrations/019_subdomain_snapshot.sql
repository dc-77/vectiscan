-- ============================================================
-- Migration 019: Subdomain-Snapshot pro scan_target (PR-M4, 2026-05-02)
-- ============================================================
-- Persistiert das Subdomain-Inventar aus Phase 0b, damit nachfolgende
-- Re-Scans desselben Targets innerhalb der TTL nicht erneut crt.sh /
-- subfinder / amass / gobuster_dns / axfr abfragen muessen.
--
-- Hintergrund TIEFENANALYSE-RUN-DRIFT-2026-05-02.md: crt.sh ist die
-- groesste externe Drift-Quelle (R1: 143b Error, R2: 50000b Vollantwort);
-- subfinder/amass schwanken um +/- 1-3 Subdomains; dnsx-Resolver-Wahl
-- aendert Reihenfolge.
-- Mit Snapshot greift bei Re-Scans innerhalb 24h ein deterministisches
-- Subdomain-Set; nur dnsx-Re-Validierung + web_probe laufen neu.
--
-- ttl_hours ist pro Eintrag konfigurierbar (Default 24h), damit Admin
-- bei Bedarf gezielt einen Snapshot kuerzer/laenger gueltig setzen kann.
-- ============================================================

CREATE TABLE IF NOT EXISTS scan_target_subdomain_snapshots (
    scan_target_id      UUID PRIMARY KEY REFERENCES scan_targets(id) ON DELETE CASCADE,
    all_subdomains      TEXT[] NOT NULL DEFAULT '{}',
    tool_sources        JSONB NOT NULL DEFAULT '{}'::jsonb,
    snapshot_ts         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ttl_hours           INTEGER NOT NULL DEFAULT 24,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_ttl_positive CHECK (ttl_hours > 0 AND ttl_hours <= 720)
);

-- Tool-sources-Format:
--   { "crtsh":   ["a.x.com", "b.x.com", ...],
--     "subfinder": [...],
--     "amass":   [...],
--     "axfr":    [...],
--     "gobuster_dns": [...] }
-- Erlaubt spaeter granulare Replays / Audit ohne Snapshot komplett zu invalidieren.

CREATE INDEX IF NOT EXISTS idx_subdomain_snapshots_ts
    ON scan_target_subdomain_snapshots(snapshot_ts);

COMMENT ON TABLE scan_target_subdomain_snapshots IS
    'PR-M4: Persistiertes Phase-0b-Subdomain-Set pro scan_target zur Re-Use bei Re-Scans innerhalb TTL.';

-- ============================================================
-- Rollback
-- ============================================================
-- DROP TABLE IF EXISTS scan_target_subdomain_snapshots;
