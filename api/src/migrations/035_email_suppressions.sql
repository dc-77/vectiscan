-- Migration 033: E-Mail-Suppression-Liste + Resend-Webhook-Idempotenz-Ledger
-- (VEC-188, Restposten F2 aus VEC-173 / VEC-169 — Reputationsschutz).
--
-- Resend stellt Bounce-/Complaint-Events via Signatur-geschützten Webhook zu
-- (`email.bounced` / `email.complained`). Die betroffene Adresse landet in
-- `email_suppressions`; jeder ausgehende Versand (`lib/email.ts`) prüft die Liste
-- VOR dem Senden und überspringt suppressed-Adressen. Das schützt die
-- Absenderreputation gegen wiederholten Versand an tote/beschwerende Adressen.
--
-- `resend_webhook_events` ist das Idempotenz-Ledger (Resend/Svix retried): die
-- Svix-Message-ID (`svix-id`) wird genau einmal beansprucht.
--
-- Additiv und rückwärtskompatibel: keine bestehende Tabelle wird verändert.
-- Rollback = DROP TABLE email_suppressions, resend_webhook_events.

CREATE TABLE IF NOT EXISTS email_suppressions (
  -- Normalisierte (trim + lowercase) Empfänger-Adresse als natürlicher PK:
  -- ein erneuter Bounce/Complaint upsertet dieselbe Zeile (idempotent).
  email TEXT PRIMARY KEY,

  -- Grund der Unterdrückung. 'manual' für operative Einträge (z. B. Opt-out).
  reason TEXT NOT NULL CHECK (reason IN ('bounce', 'complaint', 'manual')),

  -- Forensik-Kontext (Resend email_id, Event-Typ, Bounce-Subtyp …).
  detail JSONB,

  -- Auslösendes Webhook-Event (svix-id) für Nachverfolgbarkeit.
  source_event_id TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Idempotenz-Ledger der Resend-Webhook-Zustellungen (svix-id = PK).
CREATE TABLE IF NOT EXISTS resend_webhook_events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMPTZ
);
