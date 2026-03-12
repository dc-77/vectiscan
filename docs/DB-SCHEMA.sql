-- VectiScan Prototyp — Datenbankschema

-- Scans (vereinfacht, ohne Kunden/Zahlungen)
CREATE TABLE scans (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain              VARCHAR(255) NOT NULL,
    status              VARCHAR(30) NOT NULL DEFAULT 'created',
    -- Phase 0 Ergebnisse
    discovered_hosts    JSONB,
    hosts_total         INTEGER DEFAULT 0,
    hosts_completed     INTEGER DEFAULT 0,
    -- Fortschritt (wird vom Worker laufend aktualisiert)
    current_phase       VARCHAR(20),
    current_tool        VARCHAR(50),
    current_host        VARCHAR(50),
    -- Timestamps
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    -- Fehler
    error_message       TEXT,
    -- Meta
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scans_status ON scans(status);

-- Scan Results (ein Eintrag pro Tool pro Host)
CREATE TABLE scan_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID REFERENCES scans(id) ON DELETE CASCADE,
    host_ip     VARCHAR(50),
    phase       SMALLINT NOT NULL,        -- 0, 1 oder 2
    tool_name   VARCHAR(50) NOT NULL,
    raw_output  TEXT,
    exit_code   INTEGER,
    duration_ms INTEGER,
    findings    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scan_results_scan ON scan_results(scan_id);

-- Reports
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE UNIQUE,
    minio_bucket    VARCHAR(50) DEFAULT 'scan-reports',
    minio_path      VARCHAR(500) NOT NULL,
    file_size_bytes INTEGER,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);