"""S6c/N3 (spec/11 Teil 6): redirect_probe exportiert die Endantwort-Header.

Das Bestandsfeld response_headers bleibt die ERSTE Antwort (Auflage d); die
Endantwort steht im neuen Feld final_response_headers. Fixture: HL ose, wo die
erste Antwort die 143-Byte-"Redirector"-Seite ist und die Endantwort login.seam.
"""

from unittest.mock import patch

from scanner.tools import redirect_probe


class _Resp:
    def __init__(self, url, status, headers):
        self.url = url
        self.status = status
        self._h = headers

    @property
    def headers(self):
        return self._h


class _Page:
    def __init__(self, responses, final_url, title):
        self._handlers = {}
        self._responses = responses
        self.url = final_url
        self._title = title

    def on(self, event, handler):
        self._handlers[event] = handler

    def goto(self, url, **kwargs):
        for r in self._responses:
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
        self._page = page

    def new_context(self, **kwargs):
        return self._page._ctx


def test_final_response_headers_getrennt_von_erster_antwort() -> None:
    """HL ose: erste Antwort Redirector (etag), Endantwort login.seam."""
    responses = [
        _Resp("https://ose.heuel.com/",
              200,
              {"content-length": "143", "etag": "8f-5f6f0769ae580-gzip",
               "last-modified": "Wed, 15 Mar 2023 00:00:00 GMT"}),
        _Resp("https://ose.heuel.com/webmodule-ee/login.seam",
              200,
              {"content-length": "132", "x-frame-options": "SAMEORIGIN",
               "referrer-policy": "no-referrer"}),
    ]
    page = _Page(responses, final_url="https://ose.heuel.com/webmodule-ee/login.seam",
                 title="Webmodule")
    page._ctx = _Context(page)
    browser = _Browser(page)

    with patch.object(redirect_probe, "_wait_for_final_page"), \
         patch.object(redirect_probe, "_dismiss_cookie_banner"), \
         patch.object(redirect_probe, "_collect_tech_info", return_value={}), \
         patch.object(redirect_probe, "_take_screenshot", return_value=None):
        result = redirect_probe._probe_single_fqdn(browser, "ose.heuel.com", 12)

    # Bestandsfeld = erste Antwort (Redirector, etag), unveraendert.
    assert result["response_headers"].get("etag") == "8f-5f6f0769ae580-gzip"
    assert result["first_response_headers"].get("etag") == "8f-5f6f0769ae580-gzip"
    # Neues Feld = Endantwort (login.seam mit XFO und Referrer-Policy).
    assert result["final_response_headers"].get("x-frame-options") == "SAMEORIGIN"
    assert result["final_response_headers"].get("referrer-policy") == "no-referrer"
    assert "x-frame-options" not in result["response_headers"]
    # Kette traegt beide Antworten.
    assert len(result["response_chain"]) == 2
    assert result["response_chain"][-1]["url"].endswith("/login.seam")
