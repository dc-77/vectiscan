"""Tests fuer reporter.posture_aggregator (PR-Posture, 2026-05-03).

Mockt psycopg2-Connection. SQL selber wird in einer kleinen In-Memory-
Engine simuliert (dict-basiert) damit die Lifecycle-Logik testbar ist
ohne echte Postgres-Verbindung.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from reporter.posture_aggregator import (
    PostureSnapshot,
    SEVERITY_WEIGHTS,
    _calculate_posture_score,
    _derive_dedup_key,
    _extract_host_from_affected,
    _extract_path_from_affected,
    aggregate_into_posture,
)


# -----------------------------------------------------------------------------
# Pure-Funktionen
# -----------------------------------------------------------------------------

def test_extract_host_from_affected():
    assert _extract_host_from_affected("https://example.com/login") == "example.com"
    assert _extract_host_from_affected("http://x.y.com:8080/path?a=1") == "x.y.com"
    assert _extract_host_from_affected("plain.host.com") == "plain.host.com"
    assert _extract_host_from_affected(None) is None
    assert _extract_host_from_affected("") is None


def test_extract_path_from_affected():
    assert _extract_path_from_affected("https://x.com/login") == "/login"
    assert _extract_path_from_affected("https://x.com/api?q=1") == "/api"
    assert _extract_path_from_affected("https://x.com") == ""
    assert _extract_path_from_affected("") == ""


def test_derive_dedup_key_full():
    f = {"host_ip": "1.2.3.4", "policy_id": "SP-HDR-006", "url_path": "/login"}
    assert _derive_dedup_key(f) == ("1.2.3.4", "SP-HDR-006", "/login")


def test_derive_dedup_key_from_affected():
    f = {"affected": "https://example.com/api/v1", "policy_id": "SP-CSP-001"}
    assert _derive_dedup_key(f) == ("example.com", "SP-CSP-001", "/api/v1")


def test_derive_dedup_key_fallback_title():
    f = {"host_ip": "10.0.0.1", "title": "Some Issue Without policy_id"}
    key = _derive_dedup_key(f)
    assert key is not None
    assert key[0] == "10.0.0.1"
    assert key[1] == "some issue without policy_id"


def test_derive_dedup_key_returns_none_no_host():
    assert _derive_dedup_key({"policy_id": "SP-X"}) is None
    assert _derive_dedup_key({}) is None


def test_calculate_posture_score():
    # Keine Findings → 100
    assert _calculate_posture_score({}) == 100.0
    # 1 CRITICAL → 100 - 10 = 90
    assert _calculate_posture_score({"CRITICAL": 1}) == 90.0
    # 2 HIGH → 100 - 10 = 90
    assert _calculate_posture_score({"HIGH": 2}) == 90.0
    # 5 LOW → 100 - 2.5 = 97.5
    assert _calculate_posture_score({"LOW": 5}) == 97.5
    # Clamp: 20 CRITICAL = 200 penalty → 0
    assert _calculate_posture_score({"CRITICAL": 20}) == 0.0


def test_severity_weights_complete():
    assert set(SEVERITY_WEIGHTS) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


# -----------------------------------------------------------------------------
# In-Memory-Postgres-Stub fuer Lifecycle-Tests
# -----------------------------------------------------------------------------

class _FakeCursor:
    """Minimaler Stub: speichert ein dict pro Tabelle, sticht SQL ab."""

    def __init__(self, store: dict[str, list[dict[str, Any]]]):
        self.store = store
        self._fetch_queue: list = []
        self._next_returning: list = []

    def execute(self, sql: str, params: tuple = ()):
        sql_low = sql.strip().lower()

        # SELECT subscription_id FROM orders
        if "from orders where id" in sql_low:
            order_id = params[0]
            order = next((o for o in self.store["orders"] if o["id"] == order_id), None)
            self._fetch_queue = [(order["subscription_id"],)] if order else [None]
            return

        # SELECT id, status FROM consolidated_findings WHERE ... (Existing-Check)
        if "select id, status from consolidated_findings" in sql_low:
            sub_id, host_ip, ftype, port = params
            row = next(
                (cf for cf in self.store["consolidated_findings"]
                 if cf["subscription_id"] == sub_id
                 and cf["host_ip"] == host_ip
                 and cf["finding_type"] == ftype
                 and cf["port_or_path"] == port),
                None,
            )
            self._fetch_queue = [(row["id"], row["status"])] if row else [None]
            return

        # INSERT INTO consolidated_findings ... RETURNING id
        if "insert into consolidated_findings" in sql_low:
            cf_id = f"cf-{len(self.store['consolidated_findings']) + 1}"
            self.store["consolidated_findings"].append({
                "id": cf_id,
                "subscription_id": params[0],
                "host_ip": params[1],
                "finding_type": params[2],
                "port_or_path": params[3],
                "status": "open",
                "severity": params[4],
                "cvss_score": params[5],
                "title": params[6],
                "first_seen_order_id": params[9],
                "last_seen_order_id": params[10],
            })
            self._fetch_queue = [(cf_id,)]
            return

        # UPDATE consolidated_findings SET status = 'regressed' ...
        if "update consolidated_findings" in sql_low and "set status = 'regressed'" in sql_low:
            cf_id = params[-1]
            for cf in self.store["consolidated_findings"]:
                if cf["id"] == cf_id:
                    cf["status"] = "regressed"
                    cf["severity"] = params[0]
            self._fetch_queue = []
            return

        # UPDATE consolidated_findings (general) — open bleibt
        if "update consolidated_findings" in sql_low and "set status = 'resolved'" in sql_low:
            order_id = params[0]
            sub_id = params[1]
            seen_ids = params[2] if len(params) > 2 else ()
            resolved = []
            for cf in self.store["consolidated_findings"]:
                if cf["subscription_id"] == sub_id and cf["status"] in ("open", "regressed"):
                    if not seen_ids or cf["id"] not in seen_ids:
                        cf["status"] = "resolved"
                        cf["resolved_in_order_id"] = order_id
                        resolved.append((cf["id"],))
            self._fetch_queue = resolved
            return

        if "update consolidated_findings" in sql_low:
            # Open update — no-op fuer test-zwecke
            self._fetch_queue = []
            return

        # INSERT INTO scan_finding_observations
        if "into scan_finding_observations" in sql_low:
            self.store.setdefault("observations", []).append(params)
            return

        # Severity-Counts (open + regressed)
        if "select severity, count(*) from consolidated_findings" in sql_low:
            sub_id = params[0]
            counts: dict[str, int] = {}
            for cf in self.store["consolidated_findings"]:
                if cf["subscription_id"] == sub_id and cf["status"] in ("open", "regressed"):
                    counts[cf["severity"]] = counts.get(cf["severity"], 0) + 1
            self._fetch_queue = [(s, c) for s, c in counts.items()]
            return

        # Status-Counts
        if "select status, count(*)" in sql_low:
            sub_id = params[0]
            counts: dict[str, int] = {}
            for cf in self.store["consolidated_findings"]:
                if cf["subscription_id"] == sub_id:
                    counts[cf["status"]] = counts.get(cf["status"], 0) + 1
            self._fetch_queue = [(s, c) for s, c in counts.items()]
            return

        # SELECT posture_score FROM posture_history
        if "from posture_history" in sql_low:
            sub_id = params[0]
            history = [h for h in self.store.get("posture_history", []) if h["subscription_id"] == sub_id]
            history.sort(key=lambda h: h["snapshot_at"], reverse=True)
            self._fetch_queue = [(history[0]["posture_score"],)] if history else [None]
            return

        # INSERT INTO subscription_posture
        if "into subscription_posture" in sql_low:
            return

        # INSERT INTO posture_history
        if "into posture_history" in sql_low:
            self.store.setdefault("posture_history", []).append({
                "subscription_id": params[0],
                "triggering_order_id": params[1],
                "posture_score": params[2],
                "snapshot_at": len(self.store.get("posture_history", [])),  # mono-inkrementell
            })
            return

    def fetchone(self):
        return self._fetch_queue.pop(0) if self._fetch_queue else None

    def fetchall(self):
        rows = self._fetch_queue
        self._fetch_queue = []
        return rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeConn:
    def __init__(self, store):
        self.store = store
        self.committed = False

    def cursor(self, **kw):
        return _FakeCursor(self.store)

    def commit(self):
        self.committed = True


def _make_conn_with_subscription(sub_id="sub-1", order_id="ord-1"):
    store = {
        "orders": [{"id": order_id, "subscription_id": sub_id}],
        "consolidated_findings": [],
        "posture_history": [],
    }
    return _FakeConn(store), store


# -----------------------------------------------------------------------------
# Lifecycle-Tests (Aggregations-Logik)
# -----------------------------------------------------------------------------

def _make_finding(**kw):
    base = {
        "host_ip": "1.2.3.4",
        "policy_id": "SP-HDR-006",
        "url_path": "/login",
        "severity": "MEDIUM",
        "cvss_score": 5.4,
        "title": "Missing Security Header",
        "description": "...",
    }
    base.update(kw)
    return base


def test_first_scan_creates_open_findings():
    conn, store = _make_conn_with_subscription()
    findings_data = {"findings": [_make_finding()]}
    snap = aggregate_into_posture(conn, "ord-1", findings_data)
    assert snap is not None
    assert snap.new_findings == 1
    assert snap.resolved_findings == 0
    assert snap.regressed_findings == 0
    assert len(store["consolidated_findings"]) == 1
    assert store["consolidated_findings"][0]["status"] == "open"


def test_same_finding_in_second_scan_stays_open_no_dup():
    conn, store = _make_conn_with_subscription()
    findings_data = {"findings": [_make_finding()]}
    aggregate_into_posture(conn, "ord-1", findings_data)
    # 2. Order
    conn.store["orders"].append({"id": "ord-2", "subscription_id": "sub-1"})
    snap = aggregate_into_posture(conn, "ord-2", findings_data)
    # Kein neues Finding, kein resolved
    assert snap.new_findings == 0
    assert snap.resolved_findings == 0
    assert len(store["consolidated_findings"]) == 1
    assert store["consolidated_findings"][0]["status"] == "open"


def test_finding_disappears_becomes_resolved():
    conn, store = _make_conn_with_subscription()
    aggregate_into_posture(conn, "ord-1", {"findings": [_make_finding()]})
    # 2. Order ohne das Finding
    conn.store["orders"].append({"id": "ord-2", "subscription_id": "sub-1"})
    snap = aggregate_into_posture(conn, "ord-2", {"findings": []})
    assert snap.resolved_findings == 1
    assert store["consolidated_findings"][0]["status"] == "resolved"


def test_resolved_finding_returns_becomes_regressed():
    conn, store = _make_conn_with_subscription()
    aggregate_into_posture(conn, "ord-1", {"findings": [_make_finding()]})
    conn.store["orders"].append({"id": "ord-2", "subscription_id": "sub-1"})
    aggregate_into_posture(conn, "ord-2", {"findings": []})  # → resolved
    conn.store["orders"].append({"id": "ord-3", "subscription_id": "sub-1"})
    snap = aggregate_into_posture(conn, "ord-3", {"findings": [_make_finding()]})
    assert snap.regressed_findings == 1
    assert snap.has_critical_change is True  # Regression triggert Eskalation
    assert store["consolidated_findings"][0]["status"] == "regressed"


def test_no_subscription_returns_none():
    conn = _FakeConn({"orders": [{"id": "ord-1", "subscription_id": None}],
                      "consolidated_findings": []})
    snap = aggregate_into_posture(conn, "ord-1", {"findings": [_make_finding()]})
    assert snap is None


def test_critical_finding_triggers_escalation_flag():
    conn, _ = _make_conn_with_subscription()
    snap = aggregate_into_posture(
        conn, "ord-1", {"findings": [_make_finding(severity="CRITICAL")]}
    )
    assert snap.has_critical_change is True
