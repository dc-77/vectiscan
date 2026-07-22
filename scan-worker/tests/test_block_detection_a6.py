"""Tests fuer A6 (Jul 2026): Blocking-Erkennung als eigener Zustand.

Kern: die ERFASSUNG (BlockDetector.report_response) ist vom VPN-Gate
entkoppelt — der Detector laeuft IMMER, auch ohne verfuegbares VPN. Ein
geblockter Host bekommt in scan_results status="blocked" statt eines
regulaeren (Null-)Ergebnisses, und das Sticky-Verdikt landet ueber
get_block_verdicts in der Host-Struktur fuer den report-worker (C3).
"""

from unittest.mock import MagicMock, patch

import pytest

from scanner import tools


@pytest.fixture(autouse=True)
def _clear_detectors():
    """Per-Order-Detector-Map zwischen Tests leeren (Modul-Global)."""
    tools._detectors.clear()
    yield
    tools._detectors.clear()


def _make_popen(returncode=0, stdout="", stderr=""):
    proc = MagicMock()
    proc.communicate.return_value = (stdout, stderr)
    proc.returncode = returncode
    proc.pid = 4321
    return proc


# ---------------------------------------------------------------------------
# Erfassung ohne VPN
# ---------------------------------------------------------------------------

def test_record_response_creates_detector_without_vpn():
    """Ohne VPN wird der Detector jetzt trotzdem angelegt + befuellt.

    Vor A6 returnte _record_response_for_block_detection frueh bei
    not sw.is_available() — der Detector existierte ohne VPN nie.
    """
    tools._record_response_for_block_detection(
        "order-x", "10.0.0.1", "Just a moment... __cf_chl_token=abc", 0, False,
    )
    assert "order-x" in tools._detectors
    det = tools._detectors["order-x"]
    blocked, reason = det.is_blocked("10.0.0.1")
    assert blocked is True
    assert reason == "waf_body_marker"


def test_detector_detects_429_burst_without_vpn():
    """403/429-Haeufung wird OHNE VPN erfasst und als Block erkannt."""
    for _ in range(3):
        tools._record_response_for_block_detection(
            "order-y", "10.0.0.2", '{"status_code": 429, "n": 1}', 0, False,
        )
    det = tools._detectors["order-y"]
    blocked, reason = det.is_blocked("10.0.0.2")
    assert blocked is True
    assert "429_burst" in reason


def test_record_response_without_host_is_noop():
    tools._record_response_for_block_detection("order-z", None, "x", 0, False)
    assert "order-z" not in tools._detectors


# ---------------------------------------------------------------------------
# run_tool markiert geblockte Laeufe als status="blocked"
# ---------------------------------------------------------------------------

@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_run_tool_marks_blocked_on_blocked_host(mock_popen, mock_save):
    """Ist der Host geblockt, bekommt der Tool-Lauf status='blocked'."""
    # Detector vorab in den Block-Zustand bringen (3x 429).
    det = tools._get_or_create_detector("order-block")
    for _ in range(3):
        det.report_response("10.0.0.9", 429, 100)

    mock_popen.return_value = _make_popen(
        returncode=0, stdout='{"status_code": 429, "n": 1}',
    )

    tools.run_tool(
        cmd=["curl", "x"], timeout=10, order_id="order-block",
        host_ip="10.0.0.9", phase=2, tool_name="httpx",
    )

    kw = mock_save.call_args[1]
    assert kw["status"] == "blocked"
    assert kw["host_ip"] == "10.0.0.9"


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_run_tool_normal_status_when_not_blocked(mock_popen, mock_save):
    """Ohne Block-Verdikt bleibt der regulaere ok-Status erhalten."""
    mock_popen.return_value = _make_popen(returncode=0, stdout="all good")

    tools.run_tool(
        cmd=["curl", "x"], timeout=10, order_id="order-fine",
        host_ip="10.0.0.10", phase=2, tool_name="httpx",
    )

    kw = mock_save.call_args[1]
    assert kw["status"] == "ok"


@patch("scanner.tools._save_result")
@patch("scanner.tools.subprocess.Popen")
def test_run_tool_timeout_on_blocked_host_is_blocked(mock_popen, mock_save):
    """Ein Timeout auf einem geblockten Host wird als 'blocked' verbucht."""
    import subprocess as _sp

    det = tools._get_or_create_detector("order-tb")
    for _ in range(3):
        det.report_response("10.0.0.11", 429, 100)

    proc = _make_popen()
    proc.communicate.side_effect = _sp.TimeoutExpired(cmd="x", timeout=5)
    mock_popen.return_value = proc

    with patch("scanner.tools._kill_process_group"):
        tools.run_tool(
            cmd=["slow"], timeout=5, order_id="order-tb",
            host_ip="10.0.0.11", phase=2, tool_name="feroxbuster",
        )

    kw = mock_save.call_args[1]
    assert kw["status"] == "blocked"


# ---------------------------------------------------------------------------
# get_block_verdicts — Kanal in die Host-Struktur (report-worker/C3)
# ---------------------------------------------------------------------------

def test_get_block_verdicts_returns_blocked_hosts():
    det = tools._get_or_create_detector("order-v")
    for _ in range(3):
        det.report_response("10.0.0.20", 429, 100)
    det.report_response("10.0.0.21", 200, 5000)
    det.is_blocked("10.0.0.20")  # Sticky materialisieren

    verdicts = tools.get_block_verdicts("order-v")
    assert verdicts["10.0.0.20"]["blocked"] is True
    assert "429_burst" in verdicts["10.0.0.20"]["reason"]
    assert verdicts["10.0.0.21"]["blocked"] is False


def test_get_block_verdicts_unknown_order_is_empty():
    assert tools.get_block_verdicts("does-not-exist") == {}
    assert tools.get_block_verdicts(None) == {}


def test_host_block_reason_none_without_data():
    assert tools._host_block_reason("order-none", "10.0.0.99") is None
    assert tools._host_block_reason(None, "10.0.0.99") is None
