-- ============================================================
-- Migration 027: Tech-Profiles + Additional-Findings persistieren (Mai 2026)
-- ============================================================
-- Test-Session-Folge: tech_profiles werden in Phase 1 reichhaltig erfasst
-- (cms/cms_version, server-Banner, vhost_results, technologies[]) aber NIE
-- persistiert — nur intern im Reporter-Run von eol_detector + KI #5 genutzt.
-- additional_findings_summary (Findings ueber dem Top-N-Cap) ebenfalls
-- bisher nur im PDF-Anhang sichtbar, nicht in DB/API.
--
-- Diese Migration legt zwei JSONB-Spalten in `reports` an, die der
-- report-worker beim Reporter-Run mitschreibt. Frontend/Customer-Portal
-- kann sie via /api/orders/:id/findings konsumieren um pro Host eine
-- Tech-Tabelle (Name/Version/EOL/CVE-Count) anzuzeigen und alle Findings
-- (auch additional ueber Top-N) sichtbar zu machen.
-- ============================================================

-- tech_profiles[]: pro Host (per IP-Key) das vollstaendige Phase-1-Profil.
-- Format (1:1 aus scan-worker/scanner/phase1.py:build_tech_profile()):
-- {
--   "ip": "1.2.3.4",
--   "fqdns": ["example.com", "www.example.com"],
--   "cms": "WordPress" | null,
--   "cms_version": "6.4.3" | null,
--   "cms_confidence": 0.85,
--   "cms_details": { ... },
--   "server": "Apache/2.4.49" | null,
--   "waf": "Cloudflare" | null,
--   "open_ports": [80, 443, 22],
--   "mail_services": false,
--   "ftp_service": false,
--   "has_ssl": true,
--   "vhost_results": { "shop.example.com": { "cms": ..., "cms_version": ..., "waf": ... } },
--   "primary_vhost": "www.example.com" | null,
--   "technologies": [{ "name": "Apache", "version": "2.4.49" }, ...]
-- }
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS tech_profiles JSONB DEFAULT NULL;

COMMENT ON COLUMN reports.tech_profiles IS
    'Mai 2026: Phase-1-Tech-Profile pro Host (cms, server, technologies, vhost_results). Quelle fuer Per-Host-Tech-Tabelle in UI + PDF.';

-- additional_findings: Findings die durch selection.py-Top-N-Cap nicht in
-- findings_data['findings'][] gelandet sind. Voll-Body (id, title, severity,
-- description, recommendation, cvss_score, affected_hosts, policy_id) damit
-- API-Konsumenten ohne erneuten Reporter-Run alles anzeigen koennen.
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS additional_findings JSONB DEFAULT NULL;

COMMENT ON COLUMN reports.additional_findings IS
    'Mai 2026: Findings ueber Top-N-Cap (selection.py). Voll-Body damit API/Frontend "alle Befunde anzeigen" Drilldown bauen kann.';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE reports DROP COLUMN IF EXISTS tech_profiles;
-- ALTER TABLE reports DROP COLUMN IF EXISTS additional_findings;
