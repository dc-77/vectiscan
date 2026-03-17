-- VectiScan — Vollständiges Datenbankschema
-- Stand: 2026-03-17
-- Quelle: Migrationen 003–008

-- ============================================================
-- Kunden
-- ============================================================
CREATE TABLE customers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(255) NOT NULL UNIQUE,
    stripe_id   VARCHAR(255),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_customer ON users(customer_id);

-- ============================================================
-- Aufträge (Scan-Orders)
-- ============================================================
CREATE TABLE orders (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id             UUID NOT NULL REFERENCES customers(id),
    target_url              VARCHAR(2048) NOT NULL,
    target_ip               INET,
    package                 VARCHAR(20) NOT NULL DEFAULT 'professional',
    status                  VARCHAR(30) NOT NULL DEFAULT 'created',

    -- Verifizierung
    verification_method     VARCHAR(20),
    verification_token      VARCHAR(255),
    verified_at             TIMESTAMPTZ,

    -- Stripe (vorbereitet, im Prototyp nicht genutzt)
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

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_orders_package
        CHECK (package IN ('basic', 'professional', 'nis2')),
    CONSTRAINT chk_orders_verification_method
        CHECK (verification_method IS NULL
            OR verification_method IN ('dns_txt', 'file', 'meta_tag', 'manual'))
);

CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_customer ON orders(customer_id);

-- ============================================================
-- Scan-Ergebnisse (ein Eintrag pro Tool pro Host)
-- ============================================================
CREATE TABLE scan_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id    UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    host_ip     VARCHAR(50),
    phase       SMALLINT NOT NULL,          -- 0, 1 oder 2
    tool_name   VARCHAR(50) NOT NULL,       -- z.B. nmap, nuclei, ai_host_strategy, ai_phase2_config
    raw_output  TEXT,
    exit_code   INTEGER,
    duration_ms INTEGER,
    findings    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_results_order ON scan_results(order_id);

-- ============================================================
-- Reports (PDF-Berichte)
-- ============================================================
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id        UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE UNIQUE,
    minio_bucket    VARCHAR(50) DEFAULT 'scan-reports',
    minio_path      VARCHAR(500) NOT NULL,
    file_size_bytes INTEGER,
    download_token  VARCHAR(255),
    download_count  INTEGER NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,
    findings_data   JSONB,                  -- Strukturierte Claude-Befunde für Dashboard
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Audit-Log
-- ============================================================
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    order_id    UUID REFERENCES orders(id),
    action      VARCHAR(50) NOT NULL,       -- z.B. order.created, order.verified, report.downloaded
    details     JSONB,
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_order ON audit_log(order_id);

-- ============================================================
-- Wiederkehrende Scan-Zeitpläne
-- ============================================================
CREATE TABLE scan_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id     UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    target_url      VARCHAR(2048) NOT NULL,
    package         VARCHAR(20) NOT NULL DEFAULT 'professional',

    -- Zeitplan-Konfiguration
    schedule_type   VARCHAR(20) NOT NULL,   -- weekly, monthly, quarterly, once
    scheduled_at    TIMESTAMPTZ,            -- Für 'once': fester Zeitpunkt

    -- Status
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_scan_at    TIMESTAMPTZ,
    next_scan_at    TIMESTAMPTZ NOT NULL,
    last_order_id   UUID REFERENCES orders(id) ON DELETE SET NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_schedule_type
        CHECK (schedule_type IN ('weekly', 'monthly', 'quarterly', 'once')),
    CONSTRAINT chk_schedule_package
        CHECK (package IN ('basic', 'professional', 'nis2'))
);

CREATE INDEX idx_scan_schedules_next ON scan_schedules (next_scan_at) WHERE enabled = true;
CREATE INDEX idx_scan_schedules_customer ON scan_schedules (customer_id);
