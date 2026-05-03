-- ============================================================
-- Migration 020: Subscription-Posture-Modell (2026-05-03)
-- ============================================================
-- Modelliert die Customer Journey weg von "Scan-zentrisch" hin zu
-- "1 Subscription = 1 Posture-Track ueber alle Scans".
--
-- Probleme heute:
-- - Severity-Counts werden naiv ueber alle Orders einer Group summiert
--   (frontend/src/lib/grouping.ts:aggregate Z.75-80) → Doppelzaehlung
--   bei jedem Re-Scan, "Findings explodieren".
-- - Kein Lifecycle-Tracking (open/resolved/regressed/risk_accepted).
-- - Kein Subscription-Status-Report (nur pro-Scan-PDF).
--
-- Ziel:
-- - Findings ueber Scans hinweg deduplizieren auf Schluessel
--   (host_ip, finding_type, port_or_path) pro Subscription.
-- - Lifecycle-States: open, resolved, regressed, risk_accepted.
-- - Posture-Score (0-100) + Trend (improving/stable/degrading).
-- - Periodischer + on-demand + critical-Triggered Status-Report.
-- ============================================================

-- 1. subscription_posture: 1:1 zu subscriptions, akkumuliert
CREATE TABLE IF NOT EXISTS subscription_posture (
    subscription_id     UUID PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
    last_scan_order_id  UUID REFERENCES orders(id) ON DELETE SET NULL,
    last_aggregated_at  TIMESTAMPTZ,
    -- aktueller Stand pro Bucket: {open: {CRITICAL,HIGH,MEDIUM,LOW,INFO},
    --                              resolved_total, regressed_total, accepted_total}
    severity_counts     JSONB NOT NULL DEFAULT '{}'::jsonb,
    posture_score       NUMERIC(5,2),
    -- improving / stable / degrading / unknown
    trend_direction     VARCHAR(15) DEFAULT 'unknown',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. consolidated_findings: eindeutige Findings pro Subscription
CREATE TABLE IF NOT EXISTS consolidated_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    -- Dedup-Key (siehe AskUserQuestion-Antwort):
    host_ip             INET NOT NULL,
    finding_type        VARCHAR(100) NOT NULL,
    port_or_path        VARCHAR(500) NOT NULL DEFAULT '',
    -- Lifecycle:
    status              VARCHAR(20) NOT NULL DEFAULT 'open',
    severity            VARCHAR(20) NOT NULL,
    cvss_score          NUMERIC(3,1),
    title               TEXT NOT NULL,
    description         TEXT,
    -- Tracking:
    first_seen_order_id UUID REFERENCES orders(id) ON DELETE SET NULL,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_order_id  UUID REFERENCES orders(id) ON DELETE SET NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,
    resolved_in_order_id UUID REFERENCES orders(id) ON DELETE SET NULL,
    risk_accepted_at    TIMESTAMPTZ,
    risk_accepted_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    risk_accepted_reason TEXT,
    -- alles weitere (CWE, references, recommendations, scan_hints)
    metadata            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_dedup_key UNIQUE (subscription_id, host_ip, finding_type, port_or_path),
    CONSTRAINT chk_status CHECK (status IN ('open', 'resolved', 'regressed', 'risk_accepted')),
    CONSTRAINT chk_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))
);

CREATE INDEX IF NOT EXISTS idx_cf_sub_status ON consolidated_findings(subscription_id, status);
CREATE INDEX IF NOT EXISTS idx_cf_severity_open ON consolidated_findings(subscription_id, severity)
    WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_cf_first_seen ON consolidated_findings(subscription_id, first_seen_at);
CREATE INDEX IF NOT EXISTS idx_cf_last_seen_order ON consolidated_findings(last_seen_order_id);

-- 3. scan_finding_observations: pro-Scan Snapshot welche Findings present waren
CREATE TABLE IF NOT EXISTS scan_finding_observations (
    order_id                UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    consolidated_finding_id UUID NOT NULL REFERENCES consolidated_findings(id) ON DELETE CASCADE,
    observed_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- evtl. Severity-Drift zwischen Scans (z.B. CVE neu klassifiziert)
    severity_at_observation VARCHAR(20),
    PRIMARY KEY (order_id, consolidated_finding_id)
);
CREATE INDEX IF NOT EXISTS idx_sfo_order ON scan_finding_observations(order_id);
CREATE INDEX IF NOT EXISTS idx_sfo_finding ON scan_finding_observations(consolidated_finding_id);

-- 4. posture_history: Score-Snapshots pro Aggregation fuer Trend-Chart
CREATE TABLE IF NOT EXISTS posture_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    triggering_order_id UUID REFERENCES orders(id) ON DELETE SET NULL,
    snapshot_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posture_score       NUMERIC(5,2) NOT NULL,
    severity_counts     JSONB NOT NULL,
    -- Delta zum vorherigen Snapshot (fuer Status-Report)
    new_findings        INTEGER NOT NULL DEFAULT 0,
    resolved_findings   INTEGER NOT NULL DEFAULT 0,
    regressed_findings  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ph_sub_time ON posture_history(subscription_id, snapshot_at);

-- 5. subscription_status_reports: Audit-Trail der erzeugten Status-Reports
CREATE TABLE IF NOT EXISTS subscription_status_reports (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    -- 'scheduled' / 'on_demand' / 'critical_escalation'
    trigger_reason      VARCHAR(30) NOT NULL,
    posture_score       NUMERIC(5,2),
    findings_open       INTEGER,
    findings_resolved   INTEGER,
    findings_regressed  INTEGER,
    pdf_minio_key       TEXT,
    pdf_size_bytes      INTEGER,
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_by        UUID REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_ssr_sub_time ON subscription_status_reports(subscription_id, generated_at DESC);

-- 6. Subscription-Spalte fuer Trigger-Logik
ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS last_status_report_at TIMESTAMPTZ;

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE subscriptions DROP COLUMN IF EXISTS last_status_report_at;
-- DROP TABLE IF EXISTS subscription_status_reports;
-- DROP TABLE IF EXISTS posture_history;
-- DROP TABLE IF EXISTS scan_finding_observations;
-- DROP TABLE IF EXISTS consolidated_findings;
-- DROP TABLE IF EXISTS subscription_posture;
