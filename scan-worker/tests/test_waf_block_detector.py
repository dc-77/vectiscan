"""Tests fuer BlockDetector (PR-VPN, 2026-05-03)."""

from __future__ import annotations

import time

import pytest

from scanner.waf_block_detector import BlockDetector


def test_no_data_means_not_blocked():
    d = BlockDetector()
    blocked, reason = d.is_blocked("x.com")
    assert not blocked
    assert reason == "no_data"


def test_single_429_not_blocked():
    d = BlockDetector()
    d.report_response("x.com", 429, 100)
    blocked, _ = d.is_blocked("x.com")
    assert not blocked


def test_three_429_in_window_blocked():
    d = BlockDetector()
    for _ in range(3):
        d.report_response("x.com", 429, 100)
    blocked, reason = d.is_blocked("x.com")
    assert blocked
    assert "429_burst" in reason


def test_403_burst_only_after_some_2xx():
    d = BlockDetector()
    # 10x 403 ohne vorheriges 200 → noch nicht block (kann auch ein durchgehend 403-Backend sein)
    for _ in range(10):
        d.report_response("x.com", 403, 100)
    blocked, _ = d.is_blocked("x.com")
    # 10x 403 alleine reicht nicht (n_2xx=0)
    assert not blocked

    # Mit vorherigem 200 + 10x 403 → bei zwei Signalen blockt es. Ein 200 reicht
    # aber nicht — wir brauchen 2 Signale total.
    d.report_response("x.com", 200, 5000)
    blocked, _ = d.is_blocked("x.com")
    # Immer noch nur ein Signal (403_burst). Brauchen zweites.
    assert not blocked


def test_429_burst_blocks_even_with_timeouts():
    """3x 429 blockt (hard). Timeouts kippen die Entscheidung nicht mehr —
    Strang-A Befund 1: timeout_burst ist kein Block-Signal mehr, taucht also
    auch nicht mehr im Reason auf."""
    d = BlockDetector()
    for _ in range(3):
        d.report_response("x.com", 429, 50)
    for _ in range(5):
        d.report_response("x.com", 0, 0, is_timeout=True)
    blocked, reason = d.is_blocked("x.com")
    assert blocked
    assert "429_burst" in reason
    # timeout_burst darf NICHT mehr als Block-Signal erscheinen
    assert "timeout_burst" not in reason


def test_timeout_burst_only_not_blocked():
    """Strang-A Befund 1: reine Timeout-Haeufung (>=5, ohne 403/429/Marker)
    ist KEIN Block. Der Host ist tot/langsam/keine Antwort, nicht 'geblockt'."""
    d = BlockDetector()
    for _ in range(8):
        d.report_response("dead.com", 0, 0, is_timeout=True)
    blocked, reason = d.is_blocked("dead.com")
    assert not blocked
    assert "timeout_burst" not in reason
    # Auch das Sticky-Verdikt bleibt leer -> kein customer-facing "blocked"
    assert d.ever_blocked("dead.com")[0] is False
    assert "dead.com" not in d.verdicts() or d.verdicts()["dead.com"][0] is False


def test_two_soft_signals_combined_block():
    """403_burst (mit 2xx) + body_size_drop → 2 weiche → block."""
    d = BlockDetector()
    # erst grosse 200er, dann viele 403
    for _ in range(3):
        d.report_response("x.com", 200, 12000)
    for _ in range(10):
        d.report_response("x.com", 403, 100)
    blocked, reason = d.is_blocked("x.com")
    # 403_burst + body_drop = 2 soft → block
    assert blocked
    assert "403_burst_after_2xx" in reason
    assert "body_size_drop" in reason


def test_cloudflare_marker_immediately_blocks():
    d = BlockDetector()
    d.report_response(
        "x.com", 200, 800,
        body_excerpt="<html><head>Just a moment...</head><body>__cf_chl_token=abc</body>",
    )
    blocked, reason = d.is_blocked("x.com")
    assert blocked
    assert reason == "waf_body_marker"


def test_sucuri_marker_blocks():
    d = BlockDetector()
    d.report_response(
        "x.com", 403, 200,
        body_excerpt="Sucuri Website Firewall - Access Denied",
    )
    blocked, reason = d.is_blocked("x.com")
    assert blocked
    assert reason == "waf_body_marker"


def test_body_size_drop_alone_not_block():
    d = BlockDetector()
    # grosse 200, dann winzige 200 (vielleicht legitime Asset-Files)
    for _ in range(3):
        d.report_response("x.com", 200, 12000)
    for _ in range(5):
        d.report_response("x.com", 200, 100)
    # Nur body_size_drop = 1 weiches Signal → kein Block
    blocked, _ = d.is_blocked("x.com")
    assert not blocked

    # Plus 3x 429 (hard) → block
    for _ in range(3):
        d.report_response("x.com", 429, 100)
    blocked, reason = d.is_blocked("x.com")
    assert blocked
    assert "429_burst" in reason


def test_window_expires_old_events(monkeypatch):
    """Nach 60s sollten alte Events nicht mehr zaehlen."""
    d = BlockDetector()
    fake_now = [1000.0]
    monkeypatch.setattr(
        "scanner.waf_block_detector.time.monotonic",
        lambda: fake_now[0],
    )
    for _ in range(3):
        d.report_response("x.com", 429, 100)
    blocked, _ = d.is_blocked("x.com")
    assert blocked

    # 70s spaeter → window leer → nur hard_marker_hit-Flag wuerde noch wirken
    fake_now[0] = 1070.0
    blocked, _ = d.is_blocked("x.com")
    assert not blocked


def test_reset_host_cleans_state():
    d = BlockDetector()
    for _ in range(3):
        d.report_response("x.com", 429, 100)
    assert d.is_blocked("x.com")[0] is True
    d.reset_host("x.com")
    blocked, reason = d.is_blocked("x.com")
    assert not blocked
    assert reason == "no_data"


def test_per_host_isolation():
    """Block auf x.com darf y.com nicht beeinflussen."""
    d = BlockDetector()
    for _ in range(3):
        d.report_response("x.com", 429, 100)
    for _ in range(2):
        d.report_response("y.com", 429, 100)
    assert d.is_blocked("x.com")[0] is True
    assert d.is_blocked("y.com")[0] is False


# ---------------------------------------------------------------------------
# A6 (Jul 2026): Sticky-Verdikt fuer den Report (ueberlebt Window-Ablauf)
# ---------------------------------------------------------------------------

def test_ever_blocked_survives_window_expiry(monkeypatch):
    """Nach Window-Ablauf liefert is_blocked False, ever_blocked aber True."""
    d = BlockDetector()
    fake_now = [1000.0]
    monkeypatch.setattr(
        "scanner.waf_block_detector.time.monotonic",
        lambda: fake_now[0],
    )
    for _ in range(3):
        d.report_response("x.com", 429, 100)
    # is_blocked setzt den Sticky-Marker
    assert d.is_blocked("x.com")[0] is True

    # 70s spaeter: Window leer -> is_blocked False, aber Sticky bleibt
    fake_now[0] = 1070.0
    assert d.is_blocked("x.com")[0] is False
    ever_blocked, reason = d.ever_blocked("x.com")
    assert ever_blocked is True
    assert "429_burst" in reason


def test_verdicts_lists_blocked_hosts():
    d = BlockDetector()
    for _ in range(3):
        d.report_response("blocked.com", 429, 100)
    d.report_response("fine.com", 200, 5000)
    # Verdikte materialisieren (is_blocked setzt Sticky fuer blocked.com)
    d.is_blocked("blocked.com")
    verdicts = d.verdicts()
    assert verdicts["blocked.com"][0] is True
    assert "429_burst" in verdicts["blocked.com"][1]
    assert verdicts["fine.com"][0] is False


def test_reset_host_clears_sticky_verdict():
    d = BlockDetector()
    for _ in range(3):
        d.report_response("x.com", 429, 100)
    assert d.is_blocked("x.com")[0] is True
    assert d.ever_blocked("x.com")[0] is True
    d.reset_host("x.com")
    # Nach VPN-Switch: kein Sticky mehr
    assert d.ever_blocked("x.com")[0] is False
    assert "x.com" not in d.verdicts()


def test_body_marker_is_sticky_in_verdicts():
    d = BlockDetector()
    d.report_response(
        "x.com", 200, 800,
        body_excerpt="Sucuri Website Firewall - Access Denied",
    )
    d.is_blocked("x.com")  # setzt Sticky
    assert d.verdicts()["x.com"] == (True, "waf_body_marker")
