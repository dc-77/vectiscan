-- ============================================================
-- Migration 046: Defektliste eines blockierten Berichts (S5)
-- ============================================================
-- S5 (Sep 2026): Unter VECTISCAN_VALIDATION_LEVEL=strict bricht der
-- report-worker vor dem PDF ab. Bisher ging die Order dabei auf 'failed'
-- mit einem Satz Text, und die strukturierte Defektliste verschwand im
-- Log, weil sie nur ueber die reports-Zeile persistiert wurde und diese
-- im Abbruchfall nie entsteht.
--
-- Neu: Order geht auf 'report_blocked' und die Defektliste liegt hier.
--
-- Warum auf orders und nicht als reports-Zeile ohne PDF (Entscheidung DC
-- 20.09.): eine Reportzeile mit leerem minio_path waere in 16 Abfragen
-- sichtbar (has_report, Download-Token, Mailversand, ws-manager-Join) und
-- haette den Auslieferungsweg angefasst. reports.validation_warnings
-- bleibt unveraendert und wird im warn-Pfad weiter geschrieben.
--
-- Form:
--   {
--     "engine": "v3",              -- welcher Strang blockiert hat (v2|v3)
--     "level": "strict",
--     "blocked_at": "2026-09-20T18:00:00Z",
--     "defects": [{"engine":"v3","check":"abdeckungskapitel_leer",
--                  "severity":"error","finding_id":null,
--                  "message":"...","detail":{}}],
--     "unprocessed": [{"quelle":"katalog","kind":"passive_port_unverified",
--                      "what":"...","host_ip":"...","count":1}],
--     "counts": {"errors":3,"warnings":1,"unprocessed":14}
--   }
--
-- BEWUSST additiv + nullable: KEIN NOT NULL, KEIN CHECK und KEIN Backfill
-- (Rolling-Deploy-Regel wie Migration 044).
-- ============================================================

ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS report_defects JSONB DEFAULT NULL;

COMMENT ON COLUMN orders.report_defects IS
    'S5 (Sep 2026): Defektliste des letzten Berichtslaufs. Traegt engine (v2|v3), level, blocked_at, defects[{engine, check, severity, finding_id, message, detail}], unprocessed[] und counts. Gefuellt bei status report_blocked und im warn-Pfad zur Anzeige im Admin-Review. NULL wenn der Lauf ohne Defekt durchlief.';

-- ============================================================
-- Rollback
-- ============================================================
-- ALTER TABLE orders DROP COLUMN IF EXISTS report_defects;
