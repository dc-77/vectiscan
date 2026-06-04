-- Migration 033 (Juni 2026): First-Party-Analytics (VEC-36)
-- Cookieloses, DSGVO-freundliches Traffic-Tracking. Es werden KEINE
-- personenbezogenen Daten gespeichert: keine IP-Adresse, kein User-Agent,
-- kein persistenter Besucher-Identifier. Erfasst werden ausschliesslich
-- anonyme Seitenaufrufe + grobe Attribution (Referrer-Domain, UTM).
-- Dadurch ist das Tracking einwilligungsfrei nutzbar.

CREATE TABLE IF NOT EXISTS analytics_events (
    id               BIGSERIAL PRIMARY KEY,
    event_type       VARCHAR(48)  NOT NULL DEFAULT 'pageview',
    path             VARCHAR(512) NOT NULL,
    referrer_domain  VARCHAR(255),
    utm_source       VARCHAR(128),
    utm_medium       VARCHAR(128),
    utm_campaign     VARCHAR(128),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_created_at ON analytics_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analytics_path       ON analytics_events (path);
CREATE INDEX IF NOT EXISTS idx_analytics_event_type ON analytics_events (event_type);
