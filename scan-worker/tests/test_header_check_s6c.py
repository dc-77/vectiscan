"""S6c/Q8 (spec/09, spec/10 R1): header_check folgt Weiterleitungen.

Bestandsfelder (headers/security_headers/score/reachable) bleiben unveraendert;
die Endantwort-Auswertung steht im neuen Feld ``redirect_eval`` (Auflage c/d).
Fixtures aus den Antworten der Scan-Runde vom 23.09.2026.
"""

from unittest.mock import MagicMock, patch

from scanner import phase2


def _mock_curl(output: str):
    """Popen-Mock, der die curl -D - Ausgabe liefert."""
    proc = MagicMock()
    proc.communicate.return_value = (output, "")
    proc.pid = 12345
    return patch.object(phase2.subprocess, "Popen", return_value=proc)


def test_parse_header_blocks_merged_duplicate(  ) -> None:
    """CA x-powered-by: doppelter Header wird zusammengefuehrt, nicht ueberschrieben."""
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "X-Powered-By: PHP/8.4.25\r\n"
        "X-Powered-By: PleskLin\r\n"
        "Content-Type: text/html\r\n"
    )
    blocks = phase2._parse_header_blocks(raw)
    assert len(blocks) == 1
    assert blocks[0]["headers"]["x-powered-by"] == "PHP/8.4.25, PleskLin"


def test_parse_header_blocks_two_hops() -> None:
    raw = (
        "HTTP/1.1 302 Found\r\nLocation: https://o/owa/\r\n\r\n"
        "HTTP/1.1 200 OK\r\nX-Frame-Options: SAMEORIGIN\r\n"
    )
    blocks = phase2._parse_header_blocks(raw)
    assert [b["status"] for b in blocks] == [302, 200]
    assert blocks[-1]["headers"]["x-frame-options"] == "SAMEORIGIN"


def test_jw_owa_endantwort_bewertet() -> None:
    """JW .28: 302 auf /owa/, Endseite 200 mit SAMEORIGIN — Endantwort ausgewiesen."""
    out = (
        "HTTP/1.1 302 Found\r\nLocation: https://outlook.junkerwerk.de/owa/\r\nContent-Length: 0\r\n\r\n"
        "HTTP/1.1 200 OK\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Type: text/html\r\nContent-Length: 4521\r\n\r\n"
        "__VS_META__ code=200 url=https://outlook.junkerwerk.de/owa/auth/logon.aspx size=4521\n"
    )
    with _mock_curl(out):
        r = phase2._eval_redirects("https://autodiscover.junkerwerk.de/")
    assert r["reachable"] is True
    assert r["not_testable"] is False
    assert r["hops"] == [302, 200]
    assert r["final"]["status"] == 200
    assert r["final"]["headers"]["x-frame-options"] == "SAMEORIGIN"
    assert r["first"]["status"] == 302
    assert r["final"]["location"] is None  # location steht in der 302, nicht in der Endantwort


def test_hl_online_challenge_nicht_pruefbar() -> None:
    """HL online: 429 mit x-vercel-mitigated: challenge — nicht pruefbar."""
    out = (
        "HTTP/2 429 \r\nx-vercel-mitigated: challenge\r\nserver: Vercel\r\n\r\n"
        "__VS_META__ code=429 url=https://online.heuel.com/ size=0\n"
    )
    with _mock_curl(out):
        r = phase2._eval_redirects("https://online.heuel.com/")
    assert r["not_testable"] is True
    assert r["not_testable_reason"] == "challenge"


def test_ca_nextcloud_400_nicht_pruefbar() -> None:
    out = "HTTP/1.1 400 Bad Request\r\n\r\n__VS_META__ code=400 url=https://x/ size=0\n"
    with _mock_curl(out):
        r = phase2._eval_redirects("https://mailstore.castenow.de/")
    assert r["not_testable"] is True
    assert r["not_testable_reason"] == "http_4xx"


def test_bs_ftp_403_nicht_pruefbar() -> None:
    out = "HTTP/1.1 403 Forbidden\r\n\r\n__VS_META__ code=403 url=https://ftp.bergersysteme.com/ size=162\n"
    with _mock_curl(out):
        r = phase2._eval_redirects("https://ftp.bergersysteme.com/")
    assert r["not_testable"] is True
    assert r["not_testable_reason"] == "http_4xx"


def test_bs_apex_301_final_bewertet() -> None:
    """BS bergersysteme.com: 301, Endseite 200 pruefbar."""
    out = (
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.bergersysteme.com/\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "__VS_META__ code=200 url=https://www.bergersysteme.com/ size=8123\n"
    )
    with _mock_curl(out):
        r = phase2._eval_redirects("https://bergersysteme.com/")
    assert r["not_testable"] is False
    assert r["hops"] == [301, 200]
    assert r["final"]["status"] == 200


def test_ip_binding_resolve_gesetzt() -> None:
    """S6c/Q16: bei bekannter IPv4 wird --resolve gesetzt (DNS-Rotation)."""
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured["cmd"] = cmd
        proc = MagicMock()
        proc.communicate.return_value = (
            "HTTP/1.1 200 OK\r\n\r\n__VS_META__ code=200 url=https://x/ size=1\n", "")
        proc.pid = 1
        return proc

    with patch.object(phase2.subprocess, "Popen", side_effect=fake_popen):
        phase2._eval_redirects("https://www.huendgen-entsorgung.de/", ip="18.197.248.23")
    assert "--resolve" in captured["cmd"]
    assert "www.huendgen-entsorgung.de:443:18.197.248.23" in captured["cmd"]
