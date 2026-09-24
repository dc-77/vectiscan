# -*- coding: utf-8 -*-
"""Renderer v3: Reportdaten -> HTML -> PDF (Jinja2 und WeasyPrint).

Uebernommen aus ``report-prototype/build/build_report.py``. Zwei Unterschiede zum
Prototyp, beide bewusst:

* ``autoescape=True``. Der Bericht traegt Fremdtext aus den Fakten (Seitentitel,
  WHOIS-Felder, rohe Werkzeugausgaben). Ein ``<`` oder ``&`` darin zerlegt sonst das
  Dokument ab dieser Stelle. Die Stellen, die im Prototyp ``|safe`` brauchten, sind auf
  Schleifen und zwei Filter umgestellt; das erzeugte Markup ist dasselbe.
* Die Gate-Pruefungen werden nicht neu geschrieben, sondern
  ``reporter.v3.selfcheck.check_report_data`` aufgerufen. Der Renderer ergaenzt nur die
  render-spezifischen Pruefungen aus ``checks.py``.

Der Renderer blockiert nicht. Defekte stehen in ``RenderResult`` und im Log; ob eine
Order deswegen nicht ausgeliefert wird, entscheidet das Gate (Session S5).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment, PackageLoader, StrictUndefined
from markupsafe import Markup, escape

from reporter.v3.models import ReportData
from reporter.v3.selfcheck import check_report_data

from reporter.pdf.v3 import checks, screenshots as S
from reporter.pdf.v3.context import build_context
from reporter.pdf.v3.variants import Variant, variant_for

log = structlog.get_logger()

TEMPLATE = "report.html.j2"
ASSETS = Path(__file__).resolve().parent / "assets"
PLACEHOLDER = ASSETS / "screenshot-placeholder.svg"

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class RenderGateError(RuntimeError):
    """Selbstcheck oder Render-Pruefung hat Defekte gemeldet und strict ist gesetzt."""

    def __init__(self, defects: list[str]):
        self.defects = defects
        super().__init__("; ".join(defects[:5]) or "Render-Gate fehlgeschlagen")


@dataclass
class RenderResult:
    pdf_path: Path | None = None
    pages: int = 0
    words_per_page: tuple[int, ...] = ()
    sparse_pages: tuple[int, ...] = ()
    defects: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    html: str = ""
    # S6b-1 (spec/09 Teil 3): Fuellhoehe je Seite und die Layoutbefunde. ``layout_ok``
    # ist False, wenn die Seitenboxen nicht lesbar waren; dann fehlt die Pruefung.
    fill: tuple[float, ...] = ()
    kicker_pages: tuple[int, ...] = ()
    heading_pages: tuple[int, ...] = ()
    overflow: tuple[str, ...] = ()
    layout_ok: bool = False


# ----------------------------------------------------------------- Jinja-Filter

def css_string(value: Any) -> Markup:
    """Wert fuer eine CSS-Zeichenkette maskieren.

    ``@page { @bottom-left { content: "... {{ m.customer_short }} ..." } }`` ist CSS,
    nicht HTML. CSS dekodiert keine HTML-Entitaeten, ein escaptes ``&`` stuende woertlich
    als ``&amp;`` in der Fusszeile. Also nur die CSS-eigenen Sonderzeichen maskieren und
    Steuerzeichen entfernen.
    """
    text = _CTRL.sub("", str(value))
    return Markup(text.replace("\\", "\\\\").replace('"', '\\"'))


def dot_br(value: Any) -> Markup:
    """``a · b · c`` zu Zeilenumbruechen, mit Maskierung der Teile."""
    parts = str(value).split(" · ")
    return Markup("<br>").join(escape(p) for p in parts)


_ENV: Environment | None = None


def env() -> Environment:
    global _ENV
    if _ENV is None:
        _ENV = Environment(
            loader=PackageLoader("reporter.pdf.v3", "templates"),
            autoescape=True,
            undefined=StrictUndefined,
            trim_blocks=False,
            lstrip_blocks=False,
        )
        _ENV.filters["css_string"] = css_string
        _ENV.filters["dot_br"] = dot_br
    return _ENV


# ----------------------------------------------------------------- HTML

def render_html(data: ReportData | dict, *,
                resolver: S.ScreenshotResolver | None = None,
                package: str | None = None) -> tuple[str, Variant, list[str]]:
    """HTML des Berichts. Braucht kein WeasyPrint und laeuft damit ueberall."""
    meta = data.meta if isinstance(data, ReportData) else data["meta"]
    variant, warning = variant_for(meta, package)
    warnings = [warning] if warning else []

    ctx = build_context(data, variant=variant)
    if not ctx["show_screens"]:
        pass
    elif not S.available(ctx["a"].get("screens") or [], resolver or S.no_screenshots):
        # Kein einziger Bildnachweis aufloesbar: Kapitel 3.4 weglassen statt ein Raster
        # aus Platzhaltern zu setzen (das ergaebe eine halbleere Seite).
        ctx["show_screens"] = False
        warnings.append("keine Bildnachweise aufloesbar, Kapitel 3.4 entfaellt")

    return env().get_template(TEMPLATE).render(**ctx), variant, warnings


# ----------------------------------------------------------------- PDF

def _url_fetcher(resolver: S.ScreenshotResolver):
    """WeasyPrint-Fetcher fuer das Schema ``vectiscan-screenshot:``.

    Alles andere, vor allem die ``@font-face``-Verweise auf die mitgelieferten
    Inter-Dateien, geht an WeasyPrints eigenen Fetcher. Der Bericht laedt nichts aus
    dem Netz; ``allowed_protocols`` laesst nur Dateien zu.
    """
    from weasyprint.urls import URLFetcher, URLFetcherResponse

    prefix = S.SCHEME + ":"
    placeholder = PLACEHOLDER.read_bytes()
    lokal = URLFetcher(allowed_protocols=("file", "data"))

    def fetch(url: str, *args: Any, **kwargs: Any):
        if not url.startswith(prefix):
            return lokal.fetch(url)
        data = resolver(url[len(prefix):])
        if data is None:
            return URLFetcherResponse(url, body=placeholder,
                                      headers={"Content-Type": "image/svg+xml"})
        mime = "image/png" if data[:8] == b"\x89PNG\r\n\x1a\n" else "image/jpeg"
        return URLFetcherResponse(url, body=data, headers={"Content-Type": mime})

    return fetch


def render_report_v3(data: ReportData | dict, output_path: str | Path, *,
                     resolver: S.ScreenshotResolver | None = None,
                     package: str | None = None,
                     html_out: str | Path | None = None,
                     strict: bool = False) -> RenderResult:
    """Bericht als PDF. Gibt Seitenzahl, halbleere Seiten und Defekte zurueck."""
    from weasyprint import HTML

    resolver = resolver or S.no_screenshots
    html, variant, warnings = render_html(data, resolver=resolver, package=package)
    if html_out:
        Path(html_out).write_text(html, encoding="utf-8")

    defects = list(check_report_data(data))
    warnings.extend(checks.dash_check(html))

    document = HTML(string=html, base_url=str(ASSETS) + "/",
                    url_fetcher=_url_fetcher(resolver)).render()
    out = Path(output_path)
    document.write_pdf(str(out))

    words = checks.words_per_page(out)
    layout = checks.layout_scan(document)
    if layout is not None:
        # S6b-1: halbleer nach Fuellhoehe statt Wortzahl; jede solche Seite wird gemeldet.
        sparse = checks.sparse_from_fill(layout.fill)
    else:
        sparse = checks.sparse_pages(words)
        warnings.append("Layoutpruefung nicht verfuegbar (Seitenboxen nicht lesbar)")
    warnings.extend(checks.font_check(out))
    if sparse:
        warnings.append(f"halbleere Seiten {list(sparse)}")
    if layout is not None:
        for page in layout.kicker_pages:
            warnings.append(f"Kicker ohne Überschrift auf Seite {page}")
        for page in layout.heading_pages:
            warnings.append(f"Überschrift am Seitenende auf Seite {page}")
        for where in layout.overflow:
            warnings.append(f"außerhalb des Satzspiegels: {where}")

    result = RenderResult(pdf_path=out, pages=len(document.pages),
                          words_per_page=words, sparse_pages=sparse,
                          defects=defects, warnings=warnings, html=html,
                          fill=layout.fill if layout else (),
                          kicker_pages=layout.kicker_pages if layout else (),
                          heading_pages=layout.heading_pages if layout else (),
                          overflow=layout.overflow if layout else (),
                          layout_ok=layout is not None)
    log.info("pdf_v3_rendered", path=str(out), pages=result.pages,
             package=variant.key, defects=len(defects), warnings=len(warnings),
             sparse=list(sparse))
    if strict and (defects or sparse):
        raise RenderGateError(defects + [w for w in warnings if "halbleere" in w])
    return result
