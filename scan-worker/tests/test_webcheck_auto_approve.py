"""VEC-172 — Auto-Approval-Policy fuer verifizierte WebCheck-Free-Scans.

Authz-Aenderung: der Auto-Approve-Pfad gibt verifizierte anonyme WebCheck-Free-
Orders am Admin-Review-Gate frei (status ``pending_target_review`` -> ``queued``).
Diese Suite sichert die von Sven (VEC-169) geforderte Komplettmediation /
deny-by-default ab:

  (a) verifizierter webcheck-Lead         -> Auto-Approve & Scan wird enqueued
  (b) Nicht-webcheck-Order                -> UNBERUEHRT im Admin-Gate
  (c) unverifizierter / fremder Lead      -> kein Auto-Approve

plus Scope-Eskalations- und Idempotenz-/Status-Guards.

Die DB wird wie in den bestehenden Worker-Tests ueber einen gefakten
``writer._conn`` gemockt; getestet wird die Gate-Logik (welche SQL-Aktionen
laufen) und die Worker-Verdrahtung (enqueue nur bei True).
"""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from scanner.precheck import writer


class FakeCursor:
    """Minimaler psycopg2-Cursor-Ersatz: scriptbare fetchone-Antworten +
    Aufzeichnung aller execute()-Statements."""

    def __init__(self, fetch_results):
        self._fetch = list(fetch_results)
        self.executed = []  # Liste von (sql, params)
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._fetch.pop(0) if self._fetch else None


class FakeConn:
    def __init__(self, cursor):
        self._cursor = cursor
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self, *args, **kwargs):
        return self._cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def _run_with(fetch_results):
    """Fuehrt try_auto_approve_webcheck_order mit gescripteten DB-Antworten aus."""
    cur = FakeCursor(fetch_results)
    conn = FakeConn(cur)
    with patch.object(writer, "_conn", return_value=conn):
        result = writer.try_auto_approve_webcheck_order("order-123")
    return result, cur, conn


def _executed_sql(cur) -> str:
    return "\n".join(sql for sql, _ in cur.executed)


# Gate-Zeile: (status, package, target_count, verified_leads, total_targets, complete_targets)
ELIGIBLE_GATE = ("pending_target_review", "webcheck", 1, 1, 1, 1)
# Target-Zeile aus dem RETURNING: (id, discovery_policy, exclusions)
TARGET_ROW = ("target-1", "enumerate", [])


class TestAutoApproveGate:
    def test_a_verified_webcheck_is_approved_and_queued(self):
        """(a) Verifizierter webcheck-Lead -> Auto-Approve + Order auf queued."""
        result, cur, conn = _run_with([ELIGIBLE_GATE, TARGET_ROW])
        assert result is True
        assert conn.committed is True
        sql = _executed_sql(cur)
        # Target wird approved, Snapshot angelegt, Order auf queued gesetzt.
        assert "status = 'approved'" in sql
        assert "INSERT INTO scan_run_targets" in sql
        assert "status = 'queued'" in sql

    def test_b_non_webcheck_order_untouched(self):
        """(b) Nicht-webcheck-Order bleibt unberuehrt im Admin-Gate."""
        gate = ("pending_target_review", "perimeter", 1, 1, 1, 1)
        result, cur, conn = _run_with([gate])
        assert result is False
        assert conn.rolled_back is True
        sql = _executed_sql(cur)
        assert "status = 'queued'" not in sql
        assert "status = 'approved'" not in sql

    def test_c_unverified_lead_no_approve(self):
        """(c) Kein verifizierter Lead -> kein Auto-Approve."""
        gate = ("pending_target_review", "webcheck", 1, 0, 1, 1)
        result, cur, conn = _run_with([gate])
        assert result is False
        assert conn.rolled_back is True
        assert "status = 'queued'" not in _executed_sql(cur)

    def test_scope_escalation_blocked_target_count(self):
        """target_count != 1 (Scope-Eskalation) -> kein Auto-Approve."""
        gate = ("pending_target_review", "webcheck", 5, 1, 1, 1)
        result, cur, _ = _run_with([gate])
        assert result is False
        assert "status = 'queued'" not in _executed_sql(cur)

    def test_multi_target_blocked(self):
        """Mehr als 1 scan_target -> kein Auto-Approve (Scope-Eskalation)."""
        gate = ("pending_target_review", "webcheck", 1, 1, 2, 1)
        result, cur, _ = _run_with([gate])
        assert result is False
        assert "status = 'queued'" not in _executed_sql(cur)

    def test_precheck_not_complete_blocked(self):
        """Target nicht precheck_complete (z.B. failed) -> kein Auto-Approve."""
        gate = ("pending_target_review", "webcheck", 1, 1, 1, 0)
        result, cur, _ = _run_with([gate])
        assert result is False
        assert "status = 'queued'" not in _executed_sql(cur)

    def test_wrong_status_blocked(self):
        """Order nicht im Review-Gate -> kein Auto-Approve (Idempotenz/Race)."""
        gate = ("queued", "webcheck", 1, 1, 1, 1)
        result, cur, _ = _run_with([gate])
        assert result is False
        assert "status = 'approved'" not in _executed_sql(cur)

    def test_order_missing_returns_false(self):
        """Unbekannte Order -> False, kein Crash."""
        result, cur, conn = _run_with([None])
        assert result is False
        assert conn.rolled_back is True

    def test_target_vanished_rolls_back(self):
        """Gate ok, aber Target-UPDATE liefert nichts -> Rollback, False."""
        result, cur, conn = _run_with([ELIGIBLE_GATE, None])
        assert result is False
        assert conn.rolled_back is True
        assert "status = 'queued'" not in _executed_sql(cur)

    def test_guard_no_transition_returns_false(self):
        """Status-Guard greift (rowcount 0) -> False trotz Aktionen."""
        cur = FakeCursor([ELIGIBLE_GATE, TARGET_ROW])
        conn = FakeConn(cur)
        with patch.object(writer, "_conn", return_value=conn):
            # Nach dem letzten execute (UPDATE ... queued) hat die Order den
            # Status bereits verloren -> 0 betroffene Zeilen.
            original_execute = cur.execute

            def execute_then_set_rowcount(sql, params=None):
                original_execute(sql, params)
                if "status = 'queued'" in sql:
                    cur.rowcount = 0

            cur.execute = execute_then_set_rowcount
            result = writer.try_auto_approve_webcheck_order("order-123")
        assert result is False


class TestPrecheckWorkerWiring:
    """Verdrahtung in precheck_worker: Scan wird NUR bei Auto-Approve enqueued."""

    def _job_complete(self):
        return {"orderId": "order-123", "targetIds": ["t1"]}

    @patch("scanner.precheck_worker.publish_event")
    @patch("scanner.precheck_worker.runner")
    @patch("scanner.precheck_worker.writer")
    def test_auto_approve_enqueues_scan(self, mock_writer, mock_runner, mock_pub):
        from scanner import precheck_worker

        mock_runner.run_target.return_value = {"live_hosts": 1}
        mock_writer.load_target.return_value = {"id": "t1"}
        mock_writer.count_pending_targets.return_value = 0
        mock_writer.update_live_hosts_count.return_value = 1
        mock_writer.try_auto_approve_webcheck_order.return_value = True

        client = MagicMock()
        precheck_worker._handle_job(self._job_complete(), client)

        mock_writer.try_auto_approve_webcheck_order.assert_called_once_with("order-123")
        client.rpush.assert_called_once()
        queue, payload = client.rpush.call_args[0]
        assert queue == "scan-pending"
        assert json.loads(payload) == {"orderId": "order-123", "package": "webcheck"}

    @patch("scanner.precheck_worker.publish_event")
    @patch("scanner.precheck_worker.runner")
    @patch("scanner.precheck_worker.writer")
    def test_no_auto_approve_no_scan(self, mock_writer, mock_runner, mock_pub):
        from scanner import precheck_worker

        mock_runner.run_target.return_value = {"live_hosts": 1}
        mock_writer.load_target.return_value = {"id": "t1"}
        mock_writer.count_pending_targets.return_value = 0
        mock_writer.update_live_hosts_count.return_value = 1
        mock_writer.try_auto_approve_webcheck_order.return_value = False

        client = MagicMock()
        precheck_worker._handle_job(self._job_complete(), client)

        client.rpush.assert_not_called()
