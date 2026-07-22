"""Tests fuer die A7-Ergebniszeilen (classify_exit / record_tool_run / _save_result).

A7 (Jul 2026): jeder Tool-Lauf schreibt genau eine Zeile in scan_results,
inklusive der Faelle, in denen ein Tool gar nicht lief.
"""

from unittest.mock import MagicMock, patch

import pytest

from scanner import tools as scanner_tools
from scanner.tools import (
    DEFAULT_OK_EXIT_CODES,
    EXIT_CODE_SKIPPED,
    TOOL_OK_EXIT_CODES,
    classify_exit,
    record_tool_run,
)


# ------------------------------------------------------------------
# classify_exit — Exit-Code-Matrix (SSoT)
# ------------------------------------------------------------------

def test_default_ok_exit_codes_is_zero_only() -> None:
    assert DEFAULT_OK_EXIT_CODES == (0,)


@pytest.mark.parametrize(
    "tool_name,expected",
    [
        ("testssl", (0, 1)),
        ("wpscan", (0, 4, 5)),
        ("ffuf", (0, 1)),
        ("feroxbuster", (0, 1)),
        ("gobuster_dir", (0,)),
        ("gobuster_dns", (0,)),
        ("httpx", (0,)),
        ("nmap", (0,)),
        ("wafw00f", (0,)),
        ("crtsh", (0,)),
        ("subfinder", (0,)),
        ("dnsx", (0,)),
    ],
)
def test_tool_ok_exit_codes_table(tool_name: str, expected: tuple) -> None:
    """Die verstreuten Call-Site-Werte sind exakt uebernommen."""
    assert TOOL_OK_EXIT_CODES[tool_name] == expected


@pytest.mark.parametrize(
    "tool_name,exit_code,expected",
    [
        ("testssl", 0, "ok"),
        ("testssl", 1, "ok"),
        ("testssl", 2, "failed"),
        ("wpscan", 4, "ok"),
        ("wpscan", 5, "ok"),
        ("wpscan", 3, "failed"),
        ("ffuf", 1, "ok"),
        ("feroxbuster", 1, "ok"),
        ("nmap", 1, "failed"),
        ("gobuster_dns", 1, "failed"),
        ("unbekanntes_tool", 0, "ok"),
        ("unbekanntes_tool", 1, "failed"),
    ],
)
def test_classify_exit_matrix(tool_name: str, exit_code: int, expected: str) -> None:
    assert classify_exit(tool_name, exit_code) == expected


@pytest.mark.parametrize(
    "exit_code,expected",
    [(-1, "timeout"), (-2, "failed"), (-3, "skipped")],
)
def test_classify_exit_sentinels(exit_code: int, expected: str) -> None:
    """Sentinel-Codes schlagen die Tool-Tabelle — auch bei ffuf/testssl."""
    assert classify_exit("ffuf", exit_code) == expected
    assert classify_exit("testssl", exit_code) == expected


def test_classify_exit_timeout_is_not_ok_for_ffuf() -> None:
    """ffuf toleriert -1 an der Call-Site, der A7-Status bleibt 'timeout'."""
    assert classify_exit("ffuf", -1) == "timeout"


def test_classify_exit_normalizes_variant_names() -> None:
    assert classify_exit("crtsh_retry2", 0) == "ok"
    assert classify_exit("ffuf_sensitive", 1) == "ok"
    assert classify_exit("ffuf_param", 1) == "ok"
    # gobuster_dns darf nicht auf gobuster_dir gemappt werden
    assert classify_exit("gobuster_dns", 1) == "failed"


def test_classify_exit_none_is_failed() -> None:
    assert classify_exit("nmap", None) == "failed"


# ------------------------------------------------------------------
# record_tool_run
# ------------------------------------------------------------------

@patch("scanner.tools._save_result")
def test_record_tool_run_skipped_uses_sentinel_minus3(mock_save: MagicMock) -> None:
    """skipped/blocked bekommen exit_code -3 (haelt sie aus dem Live-Feed)."""
    record_tool_run("order-1", "10.0.0.1", 2, "wpscan", "skipped",
                    reason="cms_not_wordpress")

    mock_save.assert_called_once()
    kw = mock_save.call_args[1]
    assert kw["exit_code"] == EXIT_CODE_SKIPPED == -3
    assert kw["status"] == "skipped"
    assert kw["skip_reason"] == "cms_not_wordpress"
    assert kw["raw_output"] == "SKIPPED: cms_not_wordpress"


@patch("scanner.tools._save_result")
def test_record_tool_run_blocked_uses_sentinel_minus3(mock_save: MagicMock) -> None:
    record_tool_run("order-1", "10.0.0.1", 2, "nikto", "blocked", reason="waf")
    assert mock_save.call_args[1]["exit_code"] == -3
    assert mock_save.call_args[1]["status"] == "blocked"


@patch("scanner.tools._save_result")
def test_record_tool_run_derives_exit_code_from_status(mock_save: MagicMock) -> None:
    record_tool_run("order-1", None, 1, "nmap", "ok")
    assert mock_save.call_args[1]["exit_code"] == 0

    mock_save.reset_mock()
    record_tool_run("order-1", None, 1, "nmap", "timeout")
    assert mock_save.call_args[1]["exit_code"] == -1

    mock_save.reset_mock()
    record_tool_run("order-1", None, 1, "nmap", "failed")
    assert mock_save.call_args[1]["exit_code"] == -2


@patch("scanner.tools._save_result")
def test_record_tool_run_explicit_exit_code_wins(mock_save: MagicMock) -> None:
    record_tool_run("order-1", None, 2, "testssl", "ok", exit_code=1)
    assert mock_save.call_args[1]["exit_code"] == 1


@patch("scanner.tools._save_result")
def test_record_tool_run_unknown_status_falls_back_to_failed(mock_save: MagicMock) -> None:
    record_tool_run("order-1", None, 2, "nmap", "voellig_unbekannt")
    assert mock_save.call_args[1]["status"] == "failed"
    assert mock_save.call_args[1]["exit_code"] == -2


@patch("scanner.tools._save_result")
def test_record_tool_run_without_order_id_writes_nothing(mock_save: MagicMock) -> None:
    record_tool_run(None, "10.0.0.1", 2, "nmap", "ok")
    mock_save.assert_not_called()


@patch("scanner.tools._save_result")
def test_record_tool_run_truncates_tool_name_and_reason(mock_save: MagicMock) -> None:
    record_tool_run("order-1", None, 2, "x" * 90, "skipped", reason="y" * 400)
    kw = mock_save.call_args[1]
    assert len(kw["tool_name"]) == 50
    assert len(kw["skip_reason"]) == 160


@patch("scanner.tools._save_result")
def test_record_tool_run_keeps_explicit_raw_output(mock_save: MagicMock) -> None:
    record_tool_run("order-1", None, 2, "nmap", "ok", raw_output="<xml/>")
    assert mock_save.call_args[1]["raw_output"] == "<xml/>"


@patch("scanner.tools._save_result", side_effect=RuntimeError("db weg"))
def test_record_tool_run_never_raises(mock_save: MagicMock) -> None:
    """Ein Fehler beim Protokollieren darf den Scan nicht kippen."""
    record_tool_run("order-1", "10.0.0.1", 2, "nmap", "ok")  # darf nicht werfen


def test_record_tool_run_uses_module_global_save_result() -> None:
    """Regressionswaechter: kein from-Import-Alias, sonst brechen test_tools.py."""
    with patch.object(scanner_tools, "_save_result") as mock_save:
        record_tool_run("order-1", None, 2, "nmap", "ok")
        mock_save.assert_called_once()


# ------------------------------------------------------------------
# _save_result — Rolling-Deploy-Fallback
# ------------------------------------------------------------------

class _FakeUndefinedColumn(Exception):
    """Simuliert psycopg2.errors.UndefinedColumn (SQLSTATE 42703)."""
    pgcode = "42703"


@pytest.fixture(autouse=True)
def _reset_column_flag():
    """Modul-globalen Rolling-Deploy-Schalter zwischen Tests zuruecksetzen."""
    scanner_tools._HAS_RUN_STATUS_COLUMNS = None
    yield
    scanner_tools._HAS_RUN_STATUS_COLUMNS = None


def _fake_conn(cursor: MagicMock) -> MagicMock:
    conn = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cursor
    return conn


@patch("scanner.tools.get_db_connection")
def test_save_result_inserts_nine_columns(mock_conn_factory: MagicMock) -> None:
    cur = MagicMock()
    mock_conn_factory.return_value = _fake_conn(cur)

    scanner_tools._save_result(
        order_id="order-1", host_ip="10.0.0.1", phase=2, tool_name="nmap",
        raw_output="out", exit_code=0, duration_ms=5,
        status="ok", skip_reason=None,
    )

    sql, params = cur.execute.call_args[0]
    assert "status, skip_reason" in sql
    assert len(params) == 9
    assert params[7] == "ok"
    assert scanner_tools._HAS_RUN_STATUS_COLUMNS is True


@patch("scanner.tools.get_db_connection")
def test_save_result_falls_back_on_undefined_column(mock_conn_factory: MagicMock) -> None:
    """Rolling-Deploy: fehlt Migration 044, greift der 7-Spalten-INSERT."""
    cur = MagicMock()
    cur.execute.side_effect = _FakeUndefinedColumn("column status does not exist")
    retry_cur = MagicMock()
    conn = MagicMock()
    conn.cursor.return_value.__enter__.side_effect = [cur, retry_cur]
    mock_conn_factory.return_value = conn

    scanner_tools._save_result(
        order_id="order-1", host_ip=None, phase=2, tool_name="nmap",
        raw_output="out", exit_code=0, duration_ms=5, status="ok",
    )

    assert scanner_tools._HAS_RUN_STATUS_COLUMNS is False
    sql, params = retry_cur.execute.call_args[0]
    assert "status" not in sql
    assert len(params) == 7
    conn.commit.assert_called_once()


@patch("scanner.tools.get_db_connection")
def test_save_result_uses_legacy_insert_once_flag_is_false(mock_conn_factory: MagicMock) -> None:
    cur = MagicMock()
    mock_conn_factory.return_value = _fake_conn(cur)
    scanner_tools._HAS_RUN_STATUS_COLUMNS = False

    scanner_tools._save_result(
        order_id="order-1", host_ip=None, phase=2, tool_name="nmap",
        raw_output="out", exit_code=0, duration_ms=5, status="ok",
    )

    sql, params = cur.execute.call_args[0]
    assert "skip_reason" not in sql
    assert len(params) == 7


@patch("scanner.tools.get_db_connection")
def test_save_result_reraises_other_db_errors_into_log(mock_conn_factory: MagicMock) -> None:
    """Nicht-42703-Fehler duerfen NICHT als 'Spalte fehlt' fehlinterpretiert werden."""
    cur = MagicMock()
    cur.execute.side_effect = RuntimeError("deadlock")
    mock_conn_factory.return_value = _fake_conn(cur)

    scanner_tools._save_result(
        order_id="order-1", host_ip=None, phase=2, tool_name="nmap",
        raw_output="out", exit_code=0, duration_ms=5, status="ok",
    )

    # Schalter bleibt unangetastet, Fehler wird nur geloggt
    assert scanner_tools._HAS_RUN_STATUS_COLUMNS is None


def test_save_result_legacy_positional_call_still_works() -> None:
    """Rule 1: bestehende positionale Aufrufe (phase2.py:935) bleiben gueltig."""
    with patch("scanner.tools.get_db_connection") as mock_conn_factory:
        cur = MagicMock()
        mock_conn_factory.return_value = _fake_conn(cur)
        scanner_tools._save_result("order-1", "10.0.0.1", 2, "zap_spider", "out", 0, 10)
        assert cur.execute.called
