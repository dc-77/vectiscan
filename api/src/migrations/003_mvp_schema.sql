-- Migration 003: MVP-Schema — Prototyp → MVP
-- Prototyp-Daten werden verworfen (keine Produktivdaten).

-- Alte Tabellen entfernen
DROP TABLE IF EXISTS scan_results CASCADE;
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS scans CASCADE;

-- Kunden
CREATE TABLE customers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       VARCHAR(255) NOT NULL UNIQUE,
    stripe_id   VARCHAR(255),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Aufträge (ersetzt scans)
CREATE TABLE orders (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id             UUID NOT NULL REFERENCES customers(id),
    target_url              VARCHAR(2048) NOT NULL,
    target_ip               INET,
    package                 VARCHAR(20) NOT NULL DEFAULT 'professional',
    status                  VARCHAR(30) NOT NULL DEFAULT 'created',
    verification_method     VARCHAR(20),
    verification_token      VARCHAR(255),
    verified_at             TIMESTAMPTZ,
    stripe_payment_id       VARCHAR(255),
    stripe_checkout_id      VARCHAR(255),
    paid_at                 TIMESTAMPTZ,
    amount_cents            INTEGER,
    currency                VARCHAR(3) DEFAULT 'EUR',
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
            OR verification_method IN ('dns_txt', 'file', 'meta_tag'))
);

CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_customer ON orders(customer_id);

-- Scan-Ergebnisse
CREATE TABLE scan_results (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id    UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    host_ip     VARCHAR(50),
    phase       SMALLINT NOT NULL,
    tool_name   VARCHAR(50) NOT NULL,
    raw_output  TEXT,
    exit_code   INTEGER,
    duration_ms INTEGER,
    findings    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_results_order ON scan_results(order_id);

-- Reports
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id        UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE UNIQUE,
    minio_bucket    VARCHAR(50) DEFAULT 'scan-reports',
    minio_path      VARCHAR(500) NOT NULL,
    file_size_bytes INTEGER,
    download_token  VARCHAR(255),
    download_count  INTEGER NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit-Log
CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    order_id    UUID REFERENCES orders(id),
    action      VARCHAR(50) NOT NULL,
    details     JSONB,
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_order ON audit_log(order_id);
