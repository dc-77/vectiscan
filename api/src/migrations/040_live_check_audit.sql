-- 040: Live-Check (SofortScan) Scan-Audit-Log (VEC-363, Phase 1 aus VEC-360 §5/§9).
--
-- "wer/was/wann" pro durchgereichtem Live-Check-Modul. Eigene Tabelle statt
-- audit_log, weil ein Live-Check KEINE Order hat (audit_log.order_id ist FK auf
-- orders) und wir die User-Attribution + ein Status-Feld (ok/blocked/...)
-- brauchen. Dient zugleich als forensische Spur für die Abuse-Härtung (§6).
--
-- Idempotent (IF NOT EXISTS) und rückwärtskompatibel.
CREATE TABLE IF NOT EXISTS live_check_audit (
  id           BIGSERIAL PRIMARY KEY,
  user_id      UUID REFERENCES users(id),
  customer_id  UUID,
  module       VARCHAR(50) NOT NULL,
  target       VARCHAR(255) NOT NULL,
  target_ip    INET,
  status       VARCHAR(20) NOT NULL,   -- ok | blocked | rate_limited | upstream_error | invalid
  detail       TEXT,
  ip_address   INET,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_live_check_audit_user ON live_check_audit(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_live_check_audit_created ON live_check_audit(created_at DESC);
