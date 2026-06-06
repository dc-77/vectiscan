-- Migration 032: WebCheck-Free Lead-Magnet (VEC-91 / PA-11)
--
-- Öffentlicher, anonymer Self-Service-Funnel: ein nicht-eingeloggter Besucher
-- gibt E-Mail + Domain ein, weist Domain-Kontrolle nach (Reuse VerificationService)
-- und erhält genau EINEN limitierten WebCheck-Free-Scan pro verifizierter Domain
-- in einem Zeitfenster. Lead-/Marketing-Daten liegen bewusst GETRENNT von den
-- Produkt-/Kundendaten (customers/orders) — DSGVO-Datentrennung (AC5).
--
-- Diese Tabelle ist additiv und rückwärtskompatibel: keine bestehende Tabelle
-- wird verändert. Rollback = DROP TABLE webcheck_leads.

CREATE TABLE IF NOT EXISTS webcheck_leads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- Eingabe des Besuchers (AC1)
  email TEXT NOT NULL,
  domain TEXT NOT NULL,

  -- Domain-Verifizierung vor Scan (AC2) — Token-Semantik wie VerificationService
  verification_token TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  verified_at TIMESTAMPTZ,
  verification_method TEXT
    CHECK (verification_method IS NULL
           OR verification_method IN ('dns_txt', 'file', 'meta_tag')),

  -- Free-Scan-Tracking: 1 Scan pro verifizierter Domain pro Zeitfenster (AC3)
  order_id UUID REFERENCES orders(id) ON DELETE SET NULL,
  scan_started_at TIMESTAMPTZ,

  -- Lead-Capture-Felder: Quelle/Kanal/UTM, ICP, Zeitstempel (AC7, greift PA-9)
  source TEXT,
  channel TEXT,
  utm_source TEXT,
  utm_medium TEXT,
  utm_campaign TEXT,
  utm_term TEXT,
  utm_content TEXT,
  referrer TEXT,
  icp_segment TEXT,

  -- DSGVO Double-Opt-in Marketing-Einwilligung (AC5), getrennt von Produktdaten.
  -- consent_status: pending -> confirmed (DOI bestätigt) | declined | withdrawn.
  -- legal_basis dokumentiert die Rechtsgrundlage der Verarbeitung.
  consent_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (consent_status IN ('pending', 'confirmed', 'declined', 'withdrawn')),
  doi_token TEXT,
  doi_sent_at TIMESTAMPTZ,
  doi_confirmed_at TIMESTAMPTZ,
  legal_basis TEXT NOT NULL DEFAULT 'consent_doi',

  -- Missbrauchs-/Rate-Limit-Kontext (AC4)
  ip TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rate-Limit-/Lookup-Indizes (AC4): schnelle Fenster-Zählung pro Domain/E-Mail/IP.
CREATE INDEX IF NOT EXISTS idx_webcheck_leads_domain ON webcheck_leads (domain);
CREATE INDEX IF NOT EXISTS idx_webcheck_leads_email ON webcheck_leads (email);
CREATE INDEX IF NOT EXISTS idx_webcheck_leads_ip_created ON webcheck_leads (ip, created_at);
CREATE INDEX IF NOT EXISTS idx_webcheck_leads_verification_token
  ON webcheck_leads (verification_token);
CREATE INDEX IF NOT EXISTS idx_webcheck_leads_doi_token ON webcheck_leads (doi_token);

-- Fenster-Abfrage für "1 Free-Scan pro verifizierter Domain" (AC3).
CREATE INDEX IF NOT EXISTS idx_webcheck_leads_domain_scan_started
  ON webcheck_leads (domain, scan_started_at);
