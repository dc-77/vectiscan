-- 043 (VEC-486): Historische Duplikat-Reports als abgeloest markieren.
--
-- Ursache: report-worker/reporter/worker.py zaehlte `version` nur hoch, wenn
-- Findings ausgeschlossen wurden. Approve und Regenerate stellen ihre Jobs aber
-- mit `excludedFindings: []` ein (api/src/routes/orders.ts:1766 und :2004) —
-- leere Liste ist in Python falsy, also blieb version=1. Jeder Folgelauf
-- schrieb daher eine weitere reports-Zeile mit version=1 UND ueberschrieb
-- denselben MinIO-Key `{order_id}.pdf`.
--
-- Folge in Prod: 27 Orders mit mehreren version=1-Zeilen (eine mit neun), die
-- alle `superseded_by IS NULL` tragen und damit als "aktuell" gelten. Der Join
-- in api/src/lib/ws-manager.ts:71 liefert dadurch mehrere Treffer ohne
-- ORDER BY, und /report-versions zeigt dieselbe Versionsnummer mehrfach.
--
-- Diese Migration markiert pro Order alle Zeilen ausser der neuesten als von
-- dieser abgeloest. Die Auslieferung selbst ist bereits unabhaengig davon
-- repariert (streamReport liest die Groesse jetzt via statObject aus dem
-- Objekt statt aus reports.file_size_bytes) — hier geht es um konsistenten
-- Zustand, nicht um die Downloads.
--
-- Idempotent: laeuft nur ueber Zeilen mit superseded_by IS NULL und laesst
-- Orders mit genau einem Report unberuehrt.
UPDATE reports r
SET superseded_by = newest.id
FROM (
    SELECT DISTINCT ON (order_id) order_id, id
    FROM reports
    WHERE superseded_by IS NULL
    ORDER BY order_id, created_at DESC, version DESC, id DESC
) AS newest
WHERE r.order_id = newest.order_id
  AND r.superseded_by IS NULL
  AND r.id <> newest.id;
