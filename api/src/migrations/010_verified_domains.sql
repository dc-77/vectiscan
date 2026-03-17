-- Migration 010: Persistent domain verification per customer
-- Verified domains are reusable for 90 days without re-verification.

BEGIN;

CREATE TABLE IF NOT EXISTS verified_domains (
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

CREATE INDEX IF NOT EXISTS idx_verified_domains_customer ON verified_domains(customer_id);
CREATE INDEX IF NOT EXISTS idx_verified_domains_lookup ON verified_domains(customer_id, domain);

COMMIT;
