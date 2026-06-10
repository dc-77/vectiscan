-- 039: Verpflichtende, versionierte Scan-Berechtigungs-Bestaetigung am Konto
-- (VEC-364, Phase 1b aus VEC-360 §6).
--
-- Board-Vorgabe: Jeder Check erfordert ein Konto mit Firmen-E-Mail UND eine
-- verpflichtende, versionierte Berechtigungs-Bestaetigung ("Ich bestaetige, nur
-- Domains zu scannen, fuer die ich eine Genehmigung habe, und erteile diese
-- hiermit."). Diese Migration ergaenzt den Art.-7-DSGVO-analogen Nachweis am
-- users-Datensatz (vgl. webcheck_leads.consent_text_version, Migration 037):
--   * authorization_consent_version — Version des bei Registrierung bestaetigten
--     Erklaerungstextes (serverseitig autoritativ gesetzt, nicht client-getrieben)
--   * authorization_consent_at      — Zeitpunkt der Bestaetigung (Nachweis-Timestamp)
--
-- Idempotent (ADD COLUMN IF NOT EXISTS) und rueckwaertskompatibel: Bestandsnutzer
-- erhalten NULL (keine Erklaerung hinterlegt). Ein NULL bedeutet "vor Einfuehrung
-- der Pflicht angelegt" und kann spaeter ueber einen Re-Consent-Flow nachgezogen
-- werden; Neuregistrierungen erzwingen die Bestaetigung in der API.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS authorization_consent_version TEXT;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS authorization_consent_at TIMESTAMPTZ;
