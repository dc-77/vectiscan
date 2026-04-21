-- VectiScan — Vollständiges Datenbankschema
-- Stand: 2026-04-21 (Migrationen 003–013)
-- Wirksames Schema im Code: api/src/migrations/*.sql

-- ============================================================
-- Kunden
-- ============================================================
CREATE TABLE customers (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) NOT NULL UNIQUE,
    company_name  VARCHAR(255),                    -- 013
    stripe_id     VARCHAR(255),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Benutzer (Login-Accounts mit Rollen)
-- ============================================================
CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   VARCHAR(255) NOT NULL UNIQUE,
    password_hash           VARCHAR(255) NOT NULL,
    role                    VARCHAR(20) NOT NULL DEFAULT 'customer',
    customer_id             UUID REFERENCES customers(id),
    reset_token             VARCHAR(255),
    reset_token_expires_at  TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_users_role CHECK (role IN ('customer', 'admin'))
);

CREATE INDEX idx_users_email     ON users(email);
CREATE INDEX idx_users_customer  ON users(customer_id);

-- ============================================================
-- Aufträge (Scan-Orders)
-- ============================================================
CREATE TABLE orders (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id             UUID NOT NULL REFERENCES customers(id),
    target_url              VARCHAR(2048) NOT NULL,
    target_ip               INET,
    package                 VARCHAR(20) NOT NULL DEFAULT 'perimeter',
    status                  VARCHAR(30) NOT NULL DEFAULT 'created',

    -- Verifizierung
    verification_method     VARCHAR(20),
    verification_token      VARCHAR(255),
    verified_at             TIMESTAMPTZ,

    -- Stripe (vorbereitet, im Prototyp nicht aktiv)
    stripe_payment_id       VARCHAR(255),
    stripe_checkout_id      VARCHAR(255),
    paid_at                 TIMESTAMPTZ,
    amount_cents            INTEGER,
    currency                VARCHAR(3) DEFAULT 'EUR',

    -- Scan-Fortschritt
    scan_started_at         TIMESTAMPTZ,
    scan_finished_at        TIMESTAMPTZ,
    discovered_hosts        JSONB,
    hosts_total             INTEGER DEFAULT 0,
    hosts_completed         INTEGER DEFAULT 0,
    current_phase           VARCHAR(20),
    current_tool            VARCHAR(50),
    current_host            VARCHAR(50),
    error_message           TEXT,

    -- v2: Phase 0a / Phase 3 — 009
    passive_intel_summary   JSONB,
    correlation_data        JSONB,
    business_impact_score   DECIMAL(3,1),

    -- Subscription / Review-Workflow — 012
    subscription_id         UUID REFERENCES subscriptions(id),
    is_rescan               BOOLEAN NOT NULL DEFAULT false,
    reviewed_by             UUID REFERENCES users(id),
    reviewed_at             TIMESTAMPTZ,
    review_notes            TEXT,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Hinweis: TLSCompliance ist über packages.py freigeschaltet, das
    -- CHECK enthält es derzeit nicht — Validation passiert im API-Layer.
    CONSTRAINT chk_orders_package
        CHECK (package IN ('webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance')),
    CONSTRAINT chk_orders_verification_method
        CHECK (verification_method IS NULL
            OR verification_method IN ('dns_txt', 'file', 'meta_tag', 'manual'))
);

CREATE INDEX idx_orders_status         ON orders(status);
CREATE INDEX idx_orders_customer       ON orders(customer_id);
CREATE INDEX idx_orders_subscription   ON orders(subscription_id);
CREATE INDEX idx_orders_status_review  ON orders(status) WHERE status = 'pending_review';

-- Order-Status-Werte (kein CHECK):
--   verification_pending, queued, scanning, passive_intel, dns_recon,
--   scan_phase1, scan_phase2, scan_phase3, scan_complete, pending_review,
--   approved, rejected, report_generating, report_complete, delivered,
--   failed, cancelled

-- ============================================================
-- Persistente Domain-Verifizierungen (90 Tage gültig) — 010
-- ============================================================
CREATE TABLE verified_domains (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id         UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    domain              VARCHAR(255) NOT NULL,
    verification_method VARCHAR(20) NOT NULL,
    verified_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '90 days'),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_verified_domains UNIQUE (customer_id, domain),
    CONSTRAINT chk_verified_domains_method
        CHECK (verification_method IN ('dns_txt', 'file', 'meta_tag', 'manual'))
);

CREATE INDEX idx_verified_domains_customer ON verified_domains(customer_id);
CREATE INDEX idx_verified_domains_lookup   ON verified_domains(customer_id, domain);

-- ============================================================
-- Wiederkehrende Scan-Zeitpläne — 008
-- ============================================================
CREATE TABLE scan_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id     UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    target_url      VARCHAR(2048) NOT NULL,
    package         VARCHAR(20) NOT NULL DEFAULT 'perimeter',

    schedule_type   VARCHAR(20) NOT NULL,    -- weekly, monthly, quarterly, once
    scheduled_at    TIMESTAMPTZ,             -- für 'once': fester Zeitpunkt

    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_scan_at    TIMESTAMPTZ,
    next_scan_at    TIMESTAMPTZ NOT NULL,
    last_order_id   UUID REFERENCES orders(id) ON DELETE SET NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_schedule_type
        CHECK (schedule_type IN ('weekly', 'monthly', 'quarterly', 'once')),
    CONSTRAINT chk_schedule_package
        CHECK (package IN ('webcheck', 'perimeter', 'compliance', 'supplychain', 'insurance'))
);

CREATE INDEX idx_scan_schedules_next     ON scan_schedules (next_scan_at) WHERE enabled = true;
CREATE INDEX idx_scan_schedules_customer ON scan_schedules (customer_id);

-- ============================================================
-- Abonnements (Jahres-Abos, Stripe vorbereitet) — 012
-- ============================================================
CREATE TABLE subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id             UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    package                 VARCHAR(30) NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'pending',
    stripe_subscription_id  VARCHAR(255),
    stripe_price_id         VARCHAR(255),
    amount_cents            INTEGER NOT NULL DEFAULT 0,
    currency                VARCHAR(3) NOT NULL DEFAULT 'EUR',
    started_at              TIMESTAMPTZ,
    expires_at              TIMESTAMPTZ,
    scan_interval           VARCHAR(20) NOT NULL DEFAULT 'monthly',
    max_domains             INTEGER NOT NULL DEFAULT 30,
    max_rescans             INTEGER NOT NULL DEFAULT 3,
    rescans_used            INTEGER NOT NULL DEFAULT 0,
    report_emails           TEXT[] NOT NULL DEFAULT '{}',
    last_scan_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_subscription_status
        CHECK (status IN ('pending', 'active', 'expired', 'cancelled')),
    CONSTRAINT chk_subscription_package
        CHECK (package IN ('perimeter', 'insurance', 'compliance', 'supplychain', 'webcheck')),
    CONSTRAINT chk_subscription_interval
        CHECK (scan_interval IN ('weekly', 'monthly', 'quarterly'))
);

CREATE INDEX idx_subscriptions_customer ON subscriptions(customer_id);
CREATE INDEX idx_subscriptions_status   ON subscriptions(status);

-- ============================================================
-- Domains pro Abonnement (Admin-Approval-Workflow) — 012
-- ============================================================
CREATE TABLE subscription_domains (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id         UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    domain                  VARCHAR(255) NOT NULL,
    status                  VARCHAR(20) NOT NULL DEFAULT 'pending_approval',
    verified_at             TIMESTAMPTZ,
    verification_method     VARCHAR(20),
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_subscription_domain UNIQUE (subscription_id, domain),
    CONSTRAINT chk_subdomain_status
        CHECK (status IN ('pending_approval', 'approved', 'rejected', 'verified'))
);

-- ============================================================
-- Scan-Ergebnisse (ein Eintrag pro Tool pro Host)
-- ============================================================
CREATE TABLE scan_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id    UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    host_ip     VARCHAR(50),
    phase       SMALLINT NOT NULL,           -- 0, 1, 2, 3, 4 (4 = report-cost)
    tool_name   VARCHAR(50) NOT NULL,        -- nmap, nuclei, ai_host_strategy, ai_phase2_config, phase3_correlation, report_cost, *_debug
    raw_output  TEXT,
    exit_code   INTEGER,
    duration_ms INTEGER,
    findings    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_results_order ON scan_results(order_id);

-- ============================================================
-- Reports (PDF-Berichte, versioniert) — 003 + 007 + 011
-- ============================================================
CREATE TABLE reports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id          UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    minio_bucket      VARCHAR(50) DEFAULT 'scan-reports',
    minio_path        VARCHAR(500) NOT NULL,
    file_size_bytes   INTEGER,
    download_token    VARCHAR(255),
    download_count    INTEGER NOT NULL DEFAULT 0,
    expires_at        TIMESTAMPTZ,
    findings_data     JSONB,                 -- 007 — Strukturierte Claude-Befunde (Dashboard)
    version           INTEGER DEFAULT 1,     -- 011
    superseded_by     UUID REFERENCES reports(id),  -- 011
    excluded_findings JSONB DEFAULT '[]'::jsonb,    -- 011
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_order_version ON reports(order_id, version DESC);

-- Hinweis: UNIQUE-Constraint auf reports.order_id wurde in 011 entfernt,
-- damit mehrere Versionen pro Order existieren können.

-- ============================================================
-- Manuelle Finding-Ausschlüsse (Admin-Review) — 011
-- ============================================================
CREATE TABLE finding_exclusions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id        UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    finding_id      VARCHAR(20) NOT NULL,
    excluded_by     UUID NOT NULL REFERENCES users(id),
    reason          TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_exclusions_order_finding
    ON finding_exclusions(order_id, finding_id);

-- ============================================================
-- Threat-Intelligence-Cache (NVD/EPSS/KEV/ExploitDB) — 009
-- ============================================================
CREATE TABLE threat_intel_cache (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cache_key   VARCHAR(255) NOT NULL UNIQUE,
    cache_value JSONB NOT NULL,
    source      VARCHAR(50) NOT NULL,        -- nvd, epss, cisa_kev, exploitdb
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_threat_intel_cache_key     ON threat_intel_cache(cache_key);
CREATE INDEX idx_threat_intel_cache_expires ON threat_intel_cache(expires_at);

-- ============================================================
-- Audit-Log
-- ============================================================
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    order_id    UUID REFERENCES orders(id),
    action      VARCHAR(50) NOT NULL,        -- order.created, order.verified, report.downloaded,
                                             -- subscription.created, subscription.domain_approved,
                                             -- finding.excluded, order.approved, order.rejected, ...
    details     JSONB,
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_order ON audit_log(order_id);
