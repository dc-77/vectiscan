-- ============================================================
-- Migration 023: VHost-Spalte für consolidated_findings (2026-05-04)
-- ============================================================
-- Multi-VHost-Probe (Mai 2026): Eine IP kann mehrere echte Web-
-- Anwendungen beherbergen (z.B. Hetzner-/Azure-Frontdoor mit edi.* +
-- ose.* unter selber IP). Dedup-Key heute (host_ip, finding_type,
-- port_or_path) würde Findings unterschiedlicher VHosts auf derselben
-- IP fälschlich als denselben Lifecycle-Eintrag führen — Findings
-- "springen" zwischen VHosts (false-resolved/false-regressed).
--
-- Fix: vhost-Spalte als Teil des Dedup-Keys. Backfill-Default ''
-- (= "host-global", für IP-globale Tools wie testssl/nmap).
-- ============================================================

ALTER TABLE consolidated_findings
    ADD COLUMN IF NOT EXISTS vhost TEXT NOT NULL DEFAULT '';

-- UNIQUE-Constraint umstellen
ALTER TABLE consolidated_findings
    DROP CONSTRAINT IF EXISTS uq_dedup_key;
ALTER TABLE consolidated_findings
    ADD CONSTRAINT uq_dedup_key
    UNIQUE (subscription_id, host_ip, finding_type, port_or_path, vhost);

CREATE INDEX IF NOT EXISTS idx_cf_vhost
    ON consolidated_findings(subscription_id, vhost)
    WHERE vhost <> '';
