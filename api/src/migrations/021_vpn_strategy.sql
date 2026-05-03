-- ============================================================
-- Migration 021: VPN-Strategy + Audit-Trail (PR-VPN, 2026-05-03)
-- ============================================================
-- Adaptive VPN-Aktivierung wenn WAF-Block erkannt wird.
-- - subscriptions.vpn_strategy steuert pro-Abo-Verhalten
-- - orders.vpn_activations protokolliert pro Order welche VPN-IPs/
--   Locations wegen welchem Block-Reason aktiviert wurden
-- ============================================================

ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS vpn_strategy VARCHAR(20) NOT NULL DEFAULT 'auto_on_block';

ALTER TABLE subscriptions
    DROP CONSTRAINT IF EXISTS chk_vpn_strategy;

ALTER TABLE subscriptions
    ADD CONSTRAINT chk_vpn_strategy
    CHECK (vpn_strategy IN ('never', 'auto_on_block', 'always'));

COMMENT ON COLUMN subscriptions.vpn_strategy IS
    'PR-VPN: never = nie VPN nutzen (z.B. fuer Whitelist-Kunden), '
    'auto_on_block = bei WAF-Block-Detection automatisch (Default), '
    'always = jeder Scan ueber VPN.';

ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS vpn_activations JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN orders.vpn_activations IS
    'Audit-Trail: Liste von {host, reason, location, success, ts} pro Order.';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE orders DROP COLUMN IF EXISTS vpn_activations;
-- ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS chk_vpn_strategy;
-- ALTER TABLE subscriptions DROP COLUMN IF EXISTS vpn_strategy;
