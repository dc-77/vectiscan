-- Migration 004: Add 'manual' to verification_method check constraint
ALTER TABLE orders DROP CONSTRAINT IF EXISTS chk_orders_verification_method;
ALTER TABLE orders ADD CONSTRAINT chk_orders_verification_method
    CHECK (verification_method IS NULL
        OR verification_method IN ('dns_txt', 'file', 'meta_tag', 'manual'));
