"""Tests fuer A5 (Jul 2026): Nicht-Antwort != Nullergebnis.

Bleibt eine HTTP-Antwort aus, darf das Tool KEINEN "0/7"-Score behaupten,
sondern setzt den reachable:false-Marker (score=None). Ein echter 403/429
(WAF) IST eine Antwort und bleibt reachable:true (Blocking = A6).
"""

from unittest.mock import MagicMock, patch

import pytest


def _make_popen(stdout: str):
    proc = MagicMock()
    proc.communicate.return_value = (stdout, "")
    proc.pid = 9999
    return proc


# ---------------------------------------------------------------------------
# header_check — Primaerfall (tief verifiziert)
# ---------------------------------------------------------------------------

@patch("scanner.phase2.subprocess.Popen")
def test_header_check_no_response_sets_reachable_false(mock_popen, tmp_path):
    """Kein curl-Output (HEAD + GET leer) -> reachable:false, score:None."""
    from scanner.phase2 import run_header_check

    mock_popen.return_value = _make_popen(stdout="")

    result = run_header_check("example.com", "1.2.3.4", str(tmp_path), "order-1")

    assert result["reachable"] is False
    assert result["score"] is None
    assert result["security_headers"] == {}
    # Es darf KEIN present_count/"0/7" behauptet werden
    assert "0/7" not in str(result.get("score"))


@patch("scanner.phase2.subprocess.Popen")
def test_header_check_with_response_sets_reachable_true(mock_popen, tmp_path):
    """Echte Antwort -> reachable:true, belastbarer Score."""
    from scanner.phase2 import run_header_check

    headers = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "X-Frame-Options: DENY\r\n"
        "Strict-Transport-Security: max-age=31536000\r\n"
    )
    mock_popen.return_value = _make_popen(stdout=headers)

    result = run_header_check("example.com", "1.2.3.4", str(tmp_path), "order-1")

    assert result["reachable"] is True
    # x-frame-options + strict-transport-security vorhanden = 2/7
    assert result["score"] == "2/7"


@patch("scanner.phase2.subprocess.Popen")
def test_header_check_403_is_reachable(mock_popen, tmp_path):
    """Ein WAF-403 IST eine HTTP-Antwort -> reachable:true (Block = A6)."""
    from scanner.phase2 import run_header_check

    headers = (
        "HTTP/1.1 403 Forbidden\r\n"
        "Server: cloudflare\r\n"
        "cf-ray: abc123\r\n"
    )
    mock_popen.return_value = _make_popen(stdout=headers)

    result = run_header_check("example.com", "1.2.3.4", str(tmp_path), "order-1")

    assert result["reachable"] is True
    assert result["score"] is not None


@patch("scanner.phase2.subprocess.Popen")
def test_header_check_persists_reachable_false_to_disk(mock_popen, tmp_path):
    """Der Marker muss auf Disk landen (report-worker liest headers.json)."""
    import json
    import os
    from scanner.phase2 import run_header_check

    mock_popen.return_value = _make_popen(stdout="")

    run_header_check("example.com", "1.2.3.4", str(tmp_path), "order-1")

    headers_json = os.path.join(str(tmp_path), "phase2", "headers.json")
    with open(headers_json) as f:
        data = json.load(f)
    assert data["reachable"] is False
    assert data["score"] is None


# ---------------------------------------------------------------------------
# Geschwister — kein "0 gefunden = unauffaellig" bei Nicht-Antwort
# ---------------------------------------------------------------------------

@patch("scanner.phase2.run_tool", return_value=(2, 100))
def test_run_testssl_returns_none_not_empty_on_failure(mock_rt, tmp_path):
    """run_testssl liefert None (=failed), NICHT [] (=sauber ohne Findings).

    Damit unterscheidet der Downstream 'keine Antwort' von 'nichts gefunden'
    und behauptet keine unauffaellige TLS-Konfiguration.
    """
    from scanner.phase2 import run_testssl

    result = run_testssl("example.com", "1.2.3.4", str(tmp_path), "order-1")
    assert result is None
