"""Winziges, absichtlich angreifbares Testziel fuer den ZAP-Integrationstest.

Zweck: dem Active Scanner genug Angriffsflaeche geben, damit er mindestens
einen Alert liefert, und zwar ohne fremdes Image und ohne Netzzugang. Das
Ziel laeuft nur im Integrations-Compose (eigenes Docker-Netz, nicht
veroeffentlicht) und ist kein Teil des Produkts.

Angriffsflaeche, bewusst:
- ``/echo?q=`` spiegelt den Parameter unescaped in die Antwort
  (reflektiertes XSS, ZAP-Regel 40012).
- ``/search`` nimmt ein GET-Formular entgegen und spiegelt ebenfalls.
- ``/contact`` nimmt ein POST-Formular entgegen und spiegelt die Felder.
- Die Startseite verlinkt alles mit Query-Parametern, damit der Spider die
  Parameter findet. Ohne verlinkte Parameter hat der Active Scanner keine
  Einstiegspunkte.
"""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

INDEX = """<!doctype html>
<html lang="de"><head><meta charset="utf-8"><title>ZAP Testziel</title></head>
<body>
<h1>ZAP Testziel</h1>
<ul>
  <li><a href="/echo?q=hallo">Echo hallo</a></li>
  <li><a href="/echo?q=welt&amp;lang=de">Echo welt</a></li>
  <li><a href="/search?term=start&amp;page=1">Suche</a></li>
  <li><a href="/contact">Kontakt</a></li>
</ul>
<form action="/search" method="get">
  <input type="text" name="term" value="">
  <input type="text" name="page" value="1">
  <input type="submit" value="Suchen">
</form>
</body></html>"""

CONTACT = """<!doctype html>
<html lang="de"><head><meta charset="utf-8"><title>Kontakt</title></head>
<body>
<form action="/contact" method="post">
  <input type="text" name="name" value="">
  <input type="text" name="message" value="">
  <input type="submit" value="Senden">
</form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body: str, status: int = 200) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path in ("/", "/index.html"):
            self._send(INDEX)
        elif parsed.path == "/echo":
            value = (query.get("q") or [""])[0]
            # Absichtlich ohne Escaping: das ist der Befund, den ZAP finden soll.
            self._send(f"<html><body><p>Echo: {value}</p></body></html>")
        elif parsed.path == "/search":
            term = (query.get("term") or [""])[0]
            page = (query.get("page") or [""])[0]
            self._send(
                f"<html><body><h2>Treffer fuer {term}</h2>"
                f"<p>Seite {page}</p></body></html>"
            )
        elif parsed.path == "/contact":
            self._send(CONTACT)
        else:
            self._send("<html><body>not found</body></html>", status=404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        fields = parse_qs(raw)
        name = (fields.get("name") or [""])[0]
        message = (fields.get("message") or [""])[0]
        self._send(
            f"<html><body><p>Danke {name}</p><p>{message}</p></body></html>"
        )

    def log_message(self, fmt: str, *args: object) -> None:
        return  # stiller Server, die Logs kommen von ZAP


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
