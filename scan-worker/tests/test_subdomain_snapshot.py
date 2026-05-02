"""Tests fuer scanner.precheck.snapshot_store (PR-M4, 2026-05-02).

Wir testen die Public-API der Snapshot-Persistenz mit einem Mock-Cursor,
weil die Tests in CI ohne echtes Postgres laufen muessen. Die SQL selbst
ist trivial (UPSERT, SELECT mit WHERE NOW() < snapshot_ts + ttl) und
wird per integration-test in der pipeline gegen das echte Schema
verifiziert.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scanner.precheck import snapshot_store


class _FakeCursor:
    def __init__(self):
        self.rows: list[Any] = []
        self.executed: list[tuple[str, tuple]] = []
        self._next_fetch: Any = None

    def execute(self, sql: str, params: tuple = ()):
        self.executed.append((sql, params))

    def fetchone(self):
        return self._next_fetch

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeConn:
    def __init__(self, cursor: _FakeCursor):
        self._cursor = cursor
        self.committed = False

    def cursor(self, cursor_factory=None):
        return self._cursor

    def commit(self):
        self.committed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def fake_db(monkeypatch):
    cursor = _FakeCursor()
    conn = _FakeConn(cursor)

    def _conn_factory():
        return conn

    monkeypatch.setattr(snapshot_store, "_conn", _conn_factory)
    return cursor


# -----------------------------------------------------------------------------
# find_fresh_for_domain
# -----------------------------------------------------------------------------

def test_find_fresh_returns_none_for_blank_domain(fake_db):
    assert snapshot_store.find_fresh_for_domain("") is None
    assert snapshot_store.find_fresh_for_domain(None) is None
    # SQL darf nicht ausgefuehrt worden sein
    assert fake_db.executed == []


def test_find_fresh_returns_none_when_no_row(fake_db):
    fake_db._next_fetch = None
    out = snapshot_store.find_fresh_for_domain("heuel.com")
    assert out is None
    assert "LOWER(t.canonical) = %s" in fake_db.executed[0][0]
    assert fake_db.executed[0][1] == ("heuel.com",)


def test_find_fresh_returns_dict_when_row_present(fake_db):
    fake_db._next_fetch = {
        "scan_target_id": "11111111-1111-1111-1111-111111111111",
        "all_subdomains": ["a.heuel.com", "b.heuel.com", "heuel.com"],
        "tool_sources": {"crtsh": ["a.heuel.com"], "subfinder": ["b.heuel.com"]},
        "snapshot_ts": datetime.now(timezone.utc) - timedelta(hours=2),
        "ttl_hours": 24,
        "age_seconds": 7200,
    }
    out = snapshot_store.find_fresh_for_domain("HEUEL.COM")
    assert out is not None
    assert out["scan_target_id"] == "11111111-1111-1111-1111-111111111111"
    assert out["subdomains"] == ["a.heuel.com", "b.heuel.com", "heuel.com"]
    assert out["tool_sources"]["crtsh"] == ["a.heuel.com"]
    assert out["age_seconds"] == 7200
    assert out["ttl_hours"] == 24
    # Domain wird lowercased an die Query gegeben
    assert fake_db.executed[0][1] == ("heuel.com",)


# -----------------------------------------------------------------------------
# save_for_target
# -----------------------------------------------------------------------------

def test_save_normalizes_subdomains_and_dedupes(fake_db):
    snapshot_store.save_for_target(
        scan_target_id="22222222-2222-2222-2222-222222222222",
        all_subdomains=["A.x.com", "a.x.com", " B.x.com ", "", None or "c.x.com"],
        tool_sources={"crtsh": ["A.x.com", "a.x.com"], "subfinder": ["B.x.com"]},
    )
    assert fake_db.executed, "kein SQL abgesetzt"
    sql, params = fake_db.executed[0]
    assert "INSERT INTO scan_target_subdomain_snapshots" in sql
    assert "ON CONFLICT (scan_target_id) DO UPDATE" in sql
    target_id, subs, sources_json, ttl = params
    assert target_id == "22222222-2222-2222-2222-222222222222"
    assert subs == ["a.x.com", "b.x.com", "c.x.com"]
    assert ttl == snapshot_store.DEFAULT_TTL_HOURS


def test_save_ignores_empty_target(fake_db):
    snapshot_store.save_for_target("", ["a.x"], {})
    assert fake_db.executed == []


def test_save_uses_custom_ttl(fake_db):
    snapshot_store.save_for_target(
        scan_target_id="33333333-3333-3333-3333-333333333333",
        all_subdomains=["x.x"],
        tool_sources={},
        ttl_hours=72,
    )
    _, params = fake_db.executed[0]
    assert params[3] == 72


# -----------------------------------------------------------------------------
# invalidate_for_target
# -----------------------------------------------------------------------------

def test_invalidate_runs_delete(fake_db):
    snapshot_store.invalidate_for_target("44444444-4444-4444-4444-444444444444")
    sql, params = fake_db.executed[0]
    assert "DELETE FROM scan_target_subdomain_snapshots" in sql
    assert params == ("44444444-4444-4444-4444-444444444444",)
