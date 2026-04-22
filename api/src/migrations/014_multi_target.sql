-- ============================================================
-- Migration 014: Multi-Target Scan-Orchestrierung
-- ============================================================
-- Führt das Multi-Target-Modell ein: scan_targets, scan_target_hosts,
-- scan_run_targets, scan_authorizations. Ersetzt subscription_domains
-- (Alt-Daten = Probeabos und werden gelöscht).
--
-- Gehört zum Plan: MULTI-TARGET-PLAN.md
-- Annahmen: keine produktiven Daten in subscription_domains
-- ============================================================

-- ============================================================
-- 1. scan_targets: Rohe Target-Eingaben pro Order oder Subscription
-- ============================================================
CREATE TABLE scan_targets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id            UUID REFERENCES orders(id) ON DELETE CASCADE,
    subscription_id     UUID REFERENCES subscriptions(id) ON DELETE CASCADE,
    raw_input           VARCHAR(255) NOT NULL,
    canonical           VARCHAR(255) NOT NULL,
    target_type         VARCHAR(20) NOT NULL,
    discovery_policy    VARCHAR(20) NOT NULL,
    exclusions          TEXT[] NOT NULL DEFAULT '{}',
    status              VARCHAR(30) NOT NULL DEFAULT 'pending_precheck',
    review_notes        TEXT,
    approved_by         UUID REFERENCES users(id),
    approved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_target_type
        CHECK (target_type IN ('fqdn_root', 'fqdn_specific', 'ipv4', 'cidr')),
    CONSTRAINT chk_discovery_policy
        CHECK (discovery_policy IN ('enumerate', 'scoped', 'ip_only')),
    CONSTRAINT chk_target_status
        CHECK (status IN ('pending_precheck', 'precheck_running',
                          'precheck_complete', 'precheck_failed',
                          'pending_review', 'approved', 'rejected', 'removed')),
    CONSTRAINT chk_target_owner
        CHECK ((order_id IS NOT NULL AND subscription_id IS NULL) OR
               (order_id IS NULL AND subscription_id IS NOT NULL))
);

CREATE INDEX idx_scan_targets_order        ON scan_targets(order_id);
CREATE INDEX idx_scan_targets_subscription ON scan_targets(subscription_id);
CREATE INDEX idx_scan_targets_status       ON scan_targets(status);
CREATE INDEX idx_scan_targets_pending
    ON scan_targets(status)
    WHERE status IN ('pending_precheck', 'precheck_running', 'pending_review');

-- ============================================================
-- 2. scan_target_hosts: Pre-Check expandierte Hosts pro Target
-- ============================================================
CREATE TABLE scan_target_hosts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_target_id      UUID NOT NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    ip                  INET,
    fqdns               TEXT[] NOT NULL DEFAULT '{}',
    is_live             BOOLEAN NOT NULL DEFAULT false,
    ports_hint          INTEGER[] NOT NULL DEFAULT '{}',
    http_status         INTEGER,
    http_title          TEXT,
    http_final_url      TEXT,
    reverse_dns         VARCHAR(255),
    cloud_provider      VARCHAR(50),
    parking_page        BOOLEAN NOT NULL DEFAULT false,
    source              VARCHAR(20) NOT NULL,
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_host_source
        CHECK (source IN ('expansion', 'precheck_dns',
                          'precheck_httpx', 'precheck_nmap')),
    CONSTRAINT chk_cloud_provider
        CHECK (cloud_provider IS NULL OR
               cloud_provider IN ('azure', 'aws', 'gcp',
                                  'cloudflare', 'hetzner_cloud', 'other'))
);

CREATE INDEX idx_target_hosts_target ON scan_target_hosts(scan_target_id);
CREATE INDEX idx_target_hosts_live
    ON scan_target_hosts(scan_target_id)
    WHERE is_live = true;
CREATE INDEX idx_target_hosts_ip ON scan_target_hosts(ip);

-- ============================================================
-- 3. scan_run_targets: Historischer Snapshot pro Scan-Lauf
-- ============================================================
CREATE TABLE scan_run_targets (
    order_id                    UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    scan_target_id              UUID NOT NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    in_scope                    BOOLEAN NOT NULL DEFAULT true,
    out_of_scope_reason         VARCHAR(50),
    snapshot_discovery_policy   VARCHAR(20) NOT NULL,
    snapshot_exclusions         TEXT[] NOT NULL DEFAULT '{}',
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (order_id, scan_target_id),
    CONSTRAINT chk_out_of_scope_reason
        CHECK (out_of_scope_reason IS NULL OR
               out_of_scope_reason IN ('removed_by_admin',
                                       'removed_by_customer',
                                       'precheck_failed',
                                       'rejected_by_admin'))
);

CREATE INDEX idx_scan_run_targets_order ON scan_run_targets(order_id);

-- ============================================================
-- 4. scan_authorizations: Out-of-Band Autorisierungsnachweise
-- ============================================================
CREATE TABLE scan_authorizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id     UUID REFERENCES subscriptions(id) ON DELETE CASCADE,
    order_id            UUID REFERENCES orders(id) ON DELETE CASCADE,
    scan_target_id      UUID REFERENCES scan_targets(id) ON DELETE CASCADE,
    document_type       VARCHAR(30) NOT NULL,
    minio_path          VARCHAR(500) NOT NULL,
    original_filename   VARCHAR(255),
    file_size_bytes     INTEGER,
    uploaded_by         UUID NOT NULL REFERENCES users(id),
    notes               TEXT,
    valid_until         DATE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_auth_document_type
        CHECK (document_type IN ('whois_screenshot', 'signed_authorization',
                                 'email_thread', 'scan_agreement', 'other')),
    CONSTRAINT chk_auth_owner
        CHECK (subscription_id IS NOT NULL OR
               order_id IS NOT NULL OR
               scan_target_id IS NOT NULL)
);

CREATE INDEX idx_scan_auth_subscription ON scan_authorizations(subscription_id);
CREATE INDEX idx_scan_auth_order        ON scan_authorizations(order_id);
CREATE INDEX idx_scan_auth_target       ON scan_authorizations(scan_target_id);

-- ============================================================
-- 5. Erweiterungen an bestehenden Tabellen
-- ============================================================

-- orders: Multi-Target-Fähigkeit
ALTER TABLE orders
    ALTER COLUMN domain DROP NOT NULL;

ALTER TABLE orders
    ADD COLUMN target_count INTEGER NOT NULL DEFAULT 1;

ALTER TABLE orders
    ADD COLUMN live_hosts_count INTEGER;

-- orders: Erweiterte Status-Liste (keine CHECK-Constraint auf status
-- existiert in v1, bleibt so). Neue Werte:
--   precheck_running, pending_target_review
-- Bestehende bleiben:
--   verification_pending, queued, scanning, passive_intel, dns_recon,
--   scan_phase1, scan_phase2, scan_phase3, scan_complete, pending_review,
--   approved, rejected, report_generating, report_complete, delivered,
--   failed, cancelled

-- subscriptions: neue Felder
ALTER TABLE subscriptions
    ADD COLUMN max_hosts INTEGER NOT NULL DEFAULT 50;

ALTER TABLE subscriptions
    ADD COLUMN max_cidr_prefix INTEGER NOT NULL DEFAULT 24;

-- max_domains wird semantisch zu "max Eingabe-Zeilen" umgedeutet.
-- Default von 30 auf 10 reduzieren (bestehende Abos behalten ihren Wert).
ALTER TABLE subscriptions
    ALTER COLUMN max_domains SET DEFAULT 10;

-- ============================================================
-- 6. subscription_domains droppen
-- ============================================================
-- Voraussetzung: Alle produktiven Abo-Daten sind Probeabos und können
-- gelöscht werden (bestätigt im Gespräch 2026-04-22).

DROP TABLE IF EXISTS subscription_domains CASCADE;

-- ============================================================
-- 7. updated_at-Trigger für scan_targets
-- ============================================================
CREATE OR REPLACE FUNCTION scan_targets_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scan_targets_updated
    BEFORE UPDATE ON scan_targets
    FOR EACH ROW
    EXECUTE FUNCTION scan_targets_update_timestamp();

-- ============================================================
-- 8. Trigger: Order.target_count aus scan_targets hochhalten
-- ============================================================
CREATE OR REPLACE FUNCTION orders_sync_target_count()
RETURNS TRIGGER AS $$
DECLARE
    target_order_id UUID;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_order_id := OLD.order_id;
    ELSE
        target_order_id := NEW.order_id;
    END IF;

    IF target_order_id IS NOT NULL THEN
        UPDATE orders
        SET target_count = (
            SELECT COUNT(*) FROM scan_targets
            WHERE order_id = target_order_id
              AND status NOT IN ('rejected', 'removed')
        )
        WHERE id = target_order_id;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_orders_target_count
    AFTER INSERT OR UPDATE OR DELETE ON scan_targets
    FOR EACH ROW
    EXECUTE FUNCTION orders_sync_target_count();

-- ============================================================
-- ROLLBACK (auskommentiert — nur bei Bedarf ausführen)
-- ============================================================
-- ACHTUNG: Rollback ist nur unmittelbar nach Migration verlustfrei
-- möglich. Nach produktiven Multi-Target-Scans gehen Daten verloren.
--
-- DROP TRIGGER IF EXISTS trg_orders_target_count ON scan_targets;
-- DROP FUNCTION IF EXISTS orders_sync_target_count();
-- DROP TRIGGER IF EXISTS trg_scan_targets_updated ON scan_targets;
-- DROP FUNCTION IF EXISTS scan_targets_update_timestamp();
--
-- ALTER TABLE subscriptions DROP COLUMN IF EXISTS max_cidr_prefix;
-- ALTER TABLE subscriptions DROP COLUMN IF EXISTS max_hosts;
-- ALTER TABLE subscriptions ALTER COLUMN max_domains SET DEFAULT 30;
--
-- ALTER TABLE orders DROP COLUMN IF EXISTS live_hosts_count;
-- ALTER TABLE orders DROP COLUMN IF EXISTS target_count;
-- -- orders.domain bleibt nullable (Rückwärtskompatibilität)
--
-- DROP TABLE IF EXISTS scan_authorizations;
-- DROP TABLE IF EXISTS scan_run_targets;
-- DROP TABLE IF EXISTS scan_target_hosts;
-- DROP TABLE IF EXISTS scan_targets;
--
-- -- subscription_domains neu anlegen (Struktur aus Migration 012)
-- CREATE TABLE subscription_domains (
--     id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
--     subscription_id         UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
--     domain                  VARCHAR(255) NOT NULL,
--     status                  VARCHAR(20) NOT NULL DEFAULT 'pending_approval',
--     verified_at             TIMESTAMPTZ,
--     verification_method     VARCHAR(20),
--     enabled                 BOOLEAN NOT NULL DEFAULT true,
--     created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
--     CONSTRAINT uq_subscription_domain UNIQUE (subscription_id, domain)
-- );
