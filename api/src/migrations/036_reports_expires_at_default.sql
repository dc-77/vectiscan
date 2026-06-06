-- Migration 034: Default-TTL (30 Tage) auf reports.expires_at
-- (VEC-180, CL-1 aus VEC-169 — Claim-Disziplin AC6 + Privacy).
--
-- Befund (VEC-169 Sven-Claim-Gegencheck): Die /webcheck-Erfolgs-Copy sichert
-- "Link 30 Tage gueltig" zu. expires_at war seit 003_mvp_schema NULLABLE OHNE
-- DEFAULT; gesetzt wird der Wert ausschliesslich vom Report-Worker
-- (report-worker/reporter/worker.py::_create_report_record, +30 Tage). Faellt
-- dieser Pfad je weg oder schreibt ein anderer Insert-Pfad einen Report-Datensatz
-- ohne expires_at, bliebe der anonyme Download-Deeplink dauerhaft gueltig:
--   (a) Copy-Claim "30 Tage" waere falsch (AC6),
--   (b) Privacy: nie ablaufender anonymer Report-Link.
-- Die Download-Route (routes/orders.ts) erzwingt 410 NUR bei gesetztem
-- expires_at (`expiresAt && now > expiresAt`) — bei NULL greift der Ablauf nicht.
--
-- Fix (Defense-in-Depth): expires_at bekommt einen DB-DEFAULT von now()+30 Tagen.
-- Damit erhaelt JEDER Insert, der die Spalte auslaesst, automatisch die korrekte
-- TTL — unabhaengig vom Worker-Code. Der Worker setzt expires_at weiterhin
-- explizit (gleicher Wert), der DEFAULT ist reine Absicherung und aendert das
-- Verhalten des bestehenden Pfads nicht.
--
-- Additiv und rueckwaertskompatibel: bestehende Zeilen bleiben unveraendert
-- (DEFAULT gilt nur fuer kuenftige Inserts). Rollback:
--   ALTER TABLE reports ALTER COLUMN expires_at DROP DEFAULT;

ALTER TABLE reports
  ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '30 days');
