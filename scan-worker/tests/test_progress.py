"""Tests for progress tracking — Redis + PostgreSQL."""

import json
from unittest.mock import MagicMock, call, patch

import pytest


@patch("scanner.progress._get_db")
@patch("scanner.progress._get_redis")
def test_update_progress_redis_set(mock_redis_factory: MagicMock, mock_db_factory: MagicMock) -> None:
    """update_progress calls Redis SET with correct key pattern."""
    from scanner.progress import update_progress

    mock_redis = MagicMock()
    mock_redis_factory.return_value = mock_redis

    mock_conn = MagicMock()
    mock_db_factory.return_value = mock_conn

    update_progress(
        scan_id="abc-123",
        phase="scan_phase1",
        tool="nmap",
        host="10.0.0.1",
        hosts_completed=1,
        hosts_total=5,
    )

    # Verify Redis SET with correct key
    mock_redis.set.assert_called_once()
    redis_call_args = mock_redis.set.call_args
    assert redis_call_args[0][0] == "scan:progress:abc-123"

    # Verify the JSON payload
    payload = json.loads(redis_call_args[0][1])
    assert payload["scanId"] == "abc-123"
    assert payload["status"] == "scan_phase1"
    assert payload["currentTool"] == "nmap"
    assert payload["currentHost"] == "10.0.0.1"
    assert payload["hostsCompleted"] == 1
    assert payload["hostsTotal"] == 5

    # Verify expiry
    assert redis_call_args[1].get("ex") == 3600


@patch("scanner.progress._get_db")
@patch("scanner.progress._get_redis")
def test_update_progress_postgres_update(mock_redis_factory: MagicMock, mock_db_factory: MagicMock) -> None:
    """update_progress calls PostgreSQL UPDATE with correct status."""
    from scanner.progress import update_progress

    mock_redis = MagicMock()
    mock_redis_factory.return_value = mock_redis

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    mock_db_factory.return_value = mock_conn

    update_progress(
        scan_id="abc-123",
        phase="scan_phase2",
        tool="nuclei",
        host="10.0.0.2",
        hosts_completed=3,
        hosts_total=5,
    )

    # Verify execute was called with UPDATE statement
    mock_cursor.execute.assert_called_once()
    sql = mock_cursor.execute.call_args[0][0]
    params = mock_cursor.execute.call_args[0][1]

    assert "UPDATE scans" in sql
    assert params == ("scan_phase2", "scan_phase2", "nuclei", "10.0.0.2", 3, 5, "abc-123")
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


@patch("scanner.progress._get_db")
@patch("scanner.progress._get_redis")
def test_set_scan_failed_updates_redis_and_db(mock_redis_factory: MagicMock, mock_db_factory: MagicMock) -> None:
    """set_scan_failed updates both Redis and PostgreSQL with failed status."""
    from scanner.progress import set_scan_failed

    mock_redis = MagicMock()
    mock_redis_factory.return_value = mock_redis

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    mock_db_factory.return_value = mock_conn

    set_scan_failed("scan-xyz", "Timeout exceeded")

    # Verify DB update
    mock_cursor.execute.assert_called_once()
    sql = mock_cursor.execute.call_args[0][0]
    params = mock_cursor.execute.call_args[0][1]
    assert "status = 'failed'" in sql
    assert "error_message" in sql
    assert params == ("Timeout exceeded", "scan-xyz")
    mock_conn.commit.assert_called_once()

    # Verify Redis update
    mock_redis.set.assert_called_once()
    redis_args = mock_redis.set.call_args
    assert redis_args[0][0] == "scan:progress:scan-xyz"
    payload = json.loads(redis_args[0][1])
    assert payload["status"] == "failed"
    assert payload["error"] == "Timeout exceeded"
    assert payload["scanId"] == "scan-xyz"


@patch("scanner.progress._get_db")
def test_set_discovered_hosts_sets_hosts_total(mock_db_factory: MagicMock) -> None:
    """set_discovered_hosts writes correct hosts_total to the DB."""
    from scanner.progress import set_discovered_hosts

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    mock_db_factory.return_value = mock_conn

    host_inventory = {
        "domain": "example.com",
        "hosts": [
            {"ip": "1.1.1.1", "fqdns": ["a.example.com"]},
            {"ip": "2.2.2.2", "fqdns": ["b.example.com"]},
            {"ip": "3.3.3.3", "fqdns": ["c.example.com"]},
        ],
        "skipped_hosts": [],
    }

    set_discovered_hosts("scan-abc", host_inventory)

    mock_cursor.execute.assert_called_once()
    sql = mock_cursor.execute.call_args[0][0]
    params = mock_cursor.execute.call_args[0][1]

    assert "hosts_total" in sql
    assert "discovered_hosts" in sql
    # params: (json_inventory, hosts_count, scan_id)
    assert params[1] == 3  # hosts_total = len(hosts)
    assert params[2] == "scan-abc"
    mock_conn.commit.assert_called_once()


@patch("scanner.progress._get_db")
def test_set_discovered_hosts_empty_inventory(mock_db_factory: MagicMock) -> None:
    """set_discovered_hosts handles empty host list correctly."""
    from scanner.progress import set_discovered_hosts

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    mock_db_factory.return_value = mock_conn

    set_discovered_hosts("scan-empty", {"domain": "example.com", "hosts": []})

    params = mock_cursor.execute.call_args[0][1]
    assert params[1] == 0  # hosts_total = 0
