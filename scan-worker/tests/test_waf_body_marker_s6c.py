"""S6c/Q17 (spec/09): waf_body_marker nur bei belegter Sperr- oder Challenge-Seite.

Fixture: bergersysteme 198.202.211.1 (Webflow) bekam normale 200/404-Antworten und
wurde trotzdem als geblockt gefuehrt, weil ein Markenname im Inhalt stand.
"""

from scanner.waf_block_detector import BlockDetector


def test_markenname_in_normaler_200_kein_block() -> None:
    """"akamai"/"cf-ray" in einer 200-Antwort ist kein Block (BS 198.202.211.1)."""
    det = BlockDetector()
    det.report_response("198.202.211.1", 200, 8000,
                        body_excerpt="<html>powered by akamai edge, cf-ray: abc</html>")
    det.report_response("198.202.211.1", 404, 1200,
                        body_excerpt="<html>not found - akamai</html>")
    blocked, reason = det.is_blocked("198.202.211.1")
    assert blocked is False


def test_schwacher_marker_mit_block_status_blockt() -> None:
    """"incapsula" zusammen mit 403 ist ein Block."""
    det = BlockDetector()
    det.report_response("1.2.3.4", 403, 300,
                        body_excerpt="Incapsula incident ID: 1234")
    blocked, reason = det.is_blocked("1.2.3.4")
    assert blocked is True
    assert reason == "waf_body_marker"


def test_starker_marker_blockt_ohne_status() -> None:
    """Eine eindeutige Challenge-Formulierung blockt auch bei Status 0/200."""
    det = BlockDetector()
    det.report_response("5.6.7.8", 200, 500,
                        body_excerpt="Checking your browser before accessing")
    blocked, reason = det.is_blocked("5.6.7.8")
    assert blocked is True
    assert reason == "waf_body_marker"
