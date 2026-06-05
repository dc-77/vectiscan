-- 035: WebCheck-Free — Marketing-Einwilligung explizit persistieren (VEC-173).
--
-- DSGVO-Kopplungsverbot (UWG §7 / Art. 6 DSGVO): Der Scan-Dienst darf nicht an
-- die Marketing-Einwilligung gekoppelt sein. Bisher wurde die DOI-Mail im
-- /start-Handler unbedingt versendet und die Einwilligung serverseitig gar nicht
-- gespeichert — damit fehlte der Nachweis (Art. 7 Abs. 1 DSGVO) und es lag eine
-- unzulässige Kopplung vor. Diese Migration ergänzt die Nachweis-Spalten:
--   * marketing_consent   — boolescher Roh-Wert der erteilten Einwilligung
--   * consent_text_version — Version des eingewilligten Consent-Textes (Nachweis)
--
-- Idempotent (ADD COLUMN IF NOT EXISTS) und rückwärtskompatibel: Bestandszeilen
-- erhalten marketing_consent=FALSE; das bestehende consent_status-Feld bleibt
-- die Quelle der Wahrheit für den DOI-Lebenszyklus (pending->confirmed).
ALTER TABLE webcheck_leads
  ADD COLUMN IF NOT EXISTS marketing_consent BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE webcheck_leads
  ADD COLUMN IF NOT EXISTS consent_text_version TEXT;
