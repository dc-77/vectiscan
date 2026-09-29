"""S6d (C7): redirect_probe nimmt die Endantwort nur aus Navigationen im Hauptframe.

Befund aus der S6d-Planung: ``final_response_headers`` stammte "last wins" aus der
letzten Antwort ueberhaupt, weil ``page.on("response")`` auch fuer nachgeladene
Skripte, Bilder und Analytics-Aufrufe feuert. An einer echten Seite waren das fast
nie die Header des Dokuments. Jetzt zaehlt nur eine Navigation im Hauptframe; die
Kette traegt die Art je Antwort, und ``final_response_source="document"`` sagt
dem report-worker, dass er die Header als Endantwort verwenden darf.
"""

from unittest.mock import patch

from scanner.tools import redirect_probe


class _Request:
    def __init__(self, navigation: bool, resource_type: str):
        self._nav = navigation
        self.resource_type = resource_type

    def is_navigation_request(self) -> bool:
        return self._nav


class _Resp:
    def __init__(self, url, status, headers, *, navigation, resource_type, frame):
        self.url = url
        self.status = status
        self._h = headers
        self.request = _Request(navigation, resource_type)
        self.frame = frame

    @property
    def headers(self):
        return self._h


class _Page:
    def __init__(self, final_url, title):
        self._handlers = {}
        self.responses = []
        self.url = final_url
        self._title = title
        self.main_frame = object()

    def on(self, event, handler):
        self._handlers[event] = handler

    def goto(self, url, **kwargs):
        for r in self.responses:
            self._handlers["response"](r)

    def title(self):
        return self._title

    def close(self):
        pass


class _Context:
    def __init__(self, page):
        self._page = page

    def new_page(self):
        return self._page


class _Browser:
    def __init__(self, page):
        self._ctx = _Context(page)

    def new_context(self, **kwargs):
        return self._ctx


def _probe(page):
    with patch.object(redirect_probe, "_wait_for_final_page"), \
         patch.object(redirect_probe, "_dismiss_cookie_banner"), \
         patch.object(redirect_probe, "_collect_tech_info", return_value={}), \
         patch.object(redirect_probe, "_take_screenshot", return_value=None):
        return redirect_probe._probe_single_fqdn(_Browser(page), "ose.heuel.com", 12)


def test_endantwort_ist_das_dokument_nicht_die_letzte_ressource() -> None:
    """HL ose: Redirector, dann login.seam als Dokument, danach Skript und Analytics."""
    page = _Page("https://ose.heuel.com/webmodule-ee/login.seam", "Webmodule")
    main = page.main_frame
    page.responses = [
        _Resp("https://ose.heuel.com/", 200,
              {"content-length": "143", "etag": "8f-5f6f0769ae580-gzip"},
              navigation=True, resource_type="document", frame=main),
        _Resp("https://ose.heuel.com/webmodule-ee/login.seam", 200,
              {"x-frame-options": "SAMEORIGIN", "content-type": "text/html"},
              navigation=True, resource_type="document", frame=main),
        _Resp("https://ose.heuel.com/webmodule-ee/app.js", 200,
              {"content-type": "application/javascript"},
              navigation=False, resource_type="script", frame=main),
        _Resp("https://www.google-analytics.com/collect", 204,
              {"content-type": "image/gif"},
              navigation=False, resource_type="xhr", frame=main),
    ]
    result = _probe(page)

    assert result["final_response_source"] == "document"
    assert result["final_response_headers"].get("x-frame-options") == "SAMEORIGIN"
    assert result["final_status"] == 200
    # Bestandsfelder unveraendert: erste Antwort und status_code wie bisher.
    assert result["response_headers"].get("etag") == "8f-5f6f0769ae580-gzip"
    assert result["first_response_headers"].get("etag") == "8f-5f6f0769ae580-gzip"
    assert result["status_code"] == 204
    kette = result["response_chain"]
    assert [e["resource_type"] for e in kette] == ["document", "document", "script", "xhr"]
    assert [e["navigation"] for e in kette] == [True, True, False, False]


def test_navigation_in_einem_frame_zaehlt_nicht() -> None:
    """Ein iframe-Dokument (Consent-Banner, eingebettete Karte) ist nicht die Endseite."""
    page = _Page("https://www.example.de/", "Start")
    main = page.main_frame
    fremder_frame = object()
    page.responses = [
        _Resp("https://www.example.de/", 200, {"strict-transport-security": "max-age=1"},
              navigation=True, resource_type="document", frame=main),
        _Resp("https://consent.example.net/frame", 200, {"x-frame-options": "DENY"},
              navigation=True, resource_type="document", frame=fremder_frame),
    ]
    result = _probe(page)
    assert result["final_response_source"] == "document"
    assert result["final_response_headers"] == {"strict-transport-security": "max-age=1"}
    assert result["response_chain"][1]["navigation"] is False


def test_ohne_bestimmbare_art_bleibt_der_rueckfall_ohne_kennzeichen() -> None:
    """Antworten ohne request-Objekt: alter Wert, aber kein Kennzeichen document."""

    class _Bare:
        def __init__(self, url, status, headers):
            self.url = url
            self.status = status
            self.headers = headers

    page = _Page("https://www.example.de/", "Start")
    page.responses = [_Bare("https://www.example.de/", 301, {"location": "/de/"}),
                      _Bare("https://www.example.de/de/", 200, {"server": "nginx"})]
    result = _probe(page)
    assert result["final_response_source"] is None
    assert result["final_response_headers"] == {"server": "nginx"}
    assert result["response_chain"][0]["resource_type"] is None
    assert result["response_chain"][0]["navigation"] is False


def test_hilfsfunktionen_sind_defensiv() -> None:
    class _Kaputt:
        @property
        def request(self):
            raise RuntimeError("weg")

    assert redirect_probe._main_frame_navigation(_Kaputt(), object()) is None
    assert redirect_probe._resource_type(_Kaputt()) is None
