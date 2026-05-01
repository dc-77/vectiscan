"""Tests fuer threat_intel_snapshot.py — Lifecycle + Lazy-Fill.

Nutzt mock(psycopg2.connect) — kein realer DB-Zugriff. Die Logik der
SQL-Statements wird ueber Argument-Inspection verifiziert.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_db_conn():
    """Liefert einen psycopg2-Mock; Connection.cursor()-Context."""
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cur
    conn.cursor.return_value.__exit__.return_value = False
    with patch('scanner.threat_intel_snapshot._get_db_conn', return_value=conn):
        yield conn, cur


class TestGetOrCreateTodaySnapshot:
    def test_returns_existing_snapshot_id_if_today(self, mock_db_conn):
        conn, cur = mock_db_conn
        cur.fetchone.return_value = ('11111111-1111-1111-1111-111111111111',)

        from scanner.threat_intel_snapshot import get_or_create_today_snapshot_id
        result = get_or_create_today_snapshot_id()

        assert result == '11111111-1111-1111-1111-111111111111'
        # Es darf keine zweite Query (INSERT) abgesetzt worden sein
        assert cur.execute.call_count == 1
        # Erste Query ist die Existenz-Pruefung
        sql_args, _ = cur.execute.call_args_list[0]
        assert 'SELECT snapshot_id FROM threat_intel_snapshots' in sql_args[0]

    def test_creates_new_snapshot_when_none_exists_today(self, mock_db_conn):
        conn, cur = mock_db_conn
        cur.fetchone.side_effect = [
            None,  # erste Query: kein existierender Snapshot
            ('22222222-2222-2222-2222-222222222222',),  # INSERT-RETURNING
        ]

        from scanner.threat_intel_snapshot import get_or_create_today_snapshot_id
        result = get_or_create_today_snapshot_id()

        assert result == '22222222-2222-2222-2222-222222222222'
        assert cur.execute.call_count == 2
        insert_sql = cur.execute.call_args_list[1][0][0]
        assert 'INSERT INTO threat_intel_snapshots' in insert_sql
        conn.commit.assert_called_once()

    def test_returns_none_on_db_error(self):
        with patch('scanner.threat_intel_snapshot._get_db_conn',
                   side_effect=Exception('DB unreachable')):
            from scanner.threat_intel_snapshot import get_or_create_today_snapshot_id
            assert get_or_create_today_snapshot_id() is None


class TestAttachSnapshotToOrder:
    def test_updates_orders_table(self, mock_db_conn):
        conn, cur = mock_db_conn
        cur.rowcount = 1

        from scanner.threat_intel_snapshot import attach_snapshot_to_order
        ok = attach_snapshot_to_order('order-123', 'snap-456')

        assert ok is True
        sql = cur.execute.call_args[0][0]
        assert 'UPDATE orders' in sql
        assert 'threat_intel_snapshot_id' in sql
        conn.commit.assert_called_once()

    def test_returns_false_when_snapshot_id_missing(self):
        from scanner.threat_intel_snapshot import attach_snapshot_to_order
        assert attach_snapshot_to_order('order-123', None) is False
        assert attach_snapshot_to_order('order-123', '') is False


class TestGetSnapshotData:
    def test_returns_data_dict(self, mock_db_conn):
        conn, cur = mock_db_conn
        # cur.fetchone() returns dict-like (DictCursor)
        cur.fetchone.return_value = {
            'nvd_data': {'CVE-2024-1': {'cvss_score': 7.5}},
            'kev_data': {'CVE-2024-2': {'knownExploited': 'Yes'}},
            'epss_data': {'CVE-2024-1': {'epss': 0.4}},
        }

        from scanner.threat_intel_snapshot import get_snapshot_data
        data = get_snapshot_data('snap-789')

        assert data['nvd']['CVE-2024-1']['cvss_score'] == 7.5
        assert data['kev']['CVE-2024-2']['knownExploited'] == 'Yes'
        assert data['epss']['CVE-2024-1']['epss'] == 0.4

    def test_returns_empty_when_snapshot_not_found(self, mock_db_conn):
        conn, cur = mock_db_conn
        cur.fetchone.return_value = None

        from scanner.threat_intel_snapshot import get_snapshot_data
        data = get_snapshot_data('snap-999')

        assert data == {'nvd': {}, 'kev': {}, 'epss': {}}

    def test_returns_empty_dict_when_no_id(self):
        from scanner.threat_intel_snapshot import get_snapshot_data
        assert get_snapshot_data('') == {'nvd': {}, 'kev': {}, 'epss': {}}


class TestMergeIntoSnapshot:
    def test_merges_jsonb_via_concat_operator(self, mock_db_conn):
        conn, cur = mock_db_conn
        cur.rowcount = 1

        from scanner.threat_intel_snapshot import merge_into_snapshot
        ok = merge_into_snapshot(
            'snap-1',
            nvd_delta={'CVE-2025-1': {'cvss_score': 9.8}},
            kev_delta=None,
            epss_delta={'CVE-2025-1': {'epss': 0.7}},
        )

        assert ok is True
        sql = cur.execute.call_args[0][0]
        assert "nvd_data" in sql and "||" in sql  # JSONB concat
        # 4 SQL-Args: nvd-json, kev-json, epss-json, snapshot_id
        sql_args = cur.execute.call_args[0][1]
        assert len(sql_args) == 4
        nvd_arg = json.loads(sql_args[0])
        assert nvd_arg == {'CVE-2025-1': {'cvss_score': 9.8}}

    def test_noop_when_all_deltas_empty(self, mock_db_conn):
        conn, cur = mock_db_conn
        from scanner.threat_intel_snapshot import merge_into_snapshot
        ok = merge_into_snapshot('snap-1')
        assert ok is True
        cur.execute.assert_not_called()

    def test_returns_false_without_snapshot_id(self):
        from scanner.threat_intel_snapshot import merge_into_snapshot
        assert merge_into_snapshot('', nvd_delta={'X': 1}) is False
