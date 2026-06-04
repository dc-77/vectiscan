-- Migration 032 (Juni 2026): Lead-Capture / Demo-Anfragen (VEC-36)
-- Eingehende Leads aus dem Demo-Formular werden hier persistiert, BEVOR
-- die E-Mail-Zustellung an den Vertrieb versucht wird. So geht kein Lead
-- verloren, auch wenn die E-Mail-Route temporaer ausfaellt
-- ("Leads landen verlaesslich beim Vertrieb").

CREATE TABLE IF NOT EXISTS leads (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             VARCHAR(255),
    email            VARCHAR(255) NOT NULL,
    company          VARCHAR(255),
    phone            VARCHAR(64),
    target_domain    VARCHAR(255),
    package_interest VARCHAR(64),
    message          TEXT,
    source           VARCHAR(64)  NOT NULL DEFAULT 'demo_form',
    -- Attribution (cookieless, aus der URL des Erstkontakts)
    utm_source       VARCHAR(128),
    utm_medium       VARCHAR(128),
    utm_campaign     VARCHAR(128),
    referrer         VARCHAR(512),
    -- DSGVO: explizite Einwilligung zur Kontaktaufnahme
    consent          BOOLEAN NOT NULL DEFAULT FALSE,
    -- Routing an den Vertrieb: pending -> routed | failed
    routing_status   VARCHAR(32)  NOT NULL DEFAULT 'pending',
    routed_at        TIMESTAMPTZ,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_leads_routing_status
        CHECK (routing_status IN ('pending', 'routed', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_leads_created_at     ON leads (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_leads_routing_status ON leads (routing_status);
