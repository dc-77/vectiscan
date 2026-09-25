# -*- coding: utf-8 -*-
"""Render-spezifische Pruefungen.

Die inhaltlichen Pruefungen (IDs, Titel, Einstufung, Fremdreferenzen, Planbezuege,
Werkzeuge ohne Version, Zaehler) stehen in ``reporter.v3.selfcheck`` und werden von dort
aufgerufen, nicht hier wiederholt. Hier steht nur, was erst am fertigen Dokument
sichtbar wird: halbleere Seiten, fehlende Schriften und Gedankenstriche im gesetzten
Text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reporter.v3.orthography import DASHES

# Schwelle aus dem Prototyp (build_report.py): unter 90 Woertern wirkt eine Seite leer.
SPARSE_WORDS = 90
# Seite 1 ist das Deckblatt und traegt absichtlich wenig Text.
SPARSE_SKIP = (1,)

# Schriften, die das Stylesheet verlangt. Ohne sie faellt WeasyPrint still auf eine
# Ersatzschrift zurueck, und die Umlaut-Falle aus dem alten Renderer (R14) kommt wieder.
REQUIRED_FONTS = ("Inter", "DejaVu Sans Mono")

_STYLE = re.compile(r"<style>.*?</style>", re.S)
_EVIDENCE = re.compile(r'<div class="ev">.*?</div>', re.S)
_TAG = re.compile(r"<[^>]+>")


def dash_check(html: str) -> list[str]:
    """Gedankenstriche im Fliesstext (Kundenvorgabe).

    Aussen vor bleiben das Stylesheet und die Nachweisbloecke. Ein Nachweis ist
    woertliche Werkzeugausgabe und enthaelt fremde Seitentitel ("Anmelden – Nextcloud").
    ``reporter/v3`` behandelt ``evidence`` aus demselben Grund als Rohtext
    (tests/v3/test_textqualitaet.py::ROHTEXT_FELDER); Umschreiben waere Faelschung.
    """
    body = _EVIDENCE.sub("", _STYLE.sub("", html))
    n = sum(body.count(d) for d in DASHES)
    return [f"{n} Gedankenstrich(e) im Text"] if n else []


def words_per_page(pdf_path: str | Path) -> tuple[int, ...]:
    """Wortzahl je Seite aus dem fertigen PDF.

    Bewusst ueber pypdf (oeffentliche API, reines Python) statt ueber WeasyPrints
    privaten Box-Baum oder einen poppler-Subprozess.
    """
    try:
        from pypdf import PdfReader
    except ImportError:
        return ()
    reader = PdfReader(str(pdf_path))
    return tuple(len((page.extract_text() or "").split()) for page in reader.pages)


def sparse_pages(words: tuple[int, ...], *, threshold: int = SPARSE_WORDS,
                 skip: tuple[int, ...] = SPARSE_SKIP) -> tuple[int, ...]:
    return tuple(i for i, n in enumerate(words, start=1)
                 if n < threshold and i not in skip)


def embedded_fonts(pdf_path: str | Path) -> set[str]:
    """Namen der im PDF eingebetteten Schriften, ohne den Subset-Praefix."""
    try:
        from pypdf import PdfReader
    except ImportError:
        return set()
    names: set[str] = set()
    for page in PdfReader(str(pdf_path)).pages:
        fonts = (page.get("/Resources") or {}).get("/Font") or {}
        for key in fonts:
            base = str(fonts[key].get_object().get("/BaseFont") or "")
            names.add(base.lstrip("/").split("+", 1)[-1])
    return names


def _flach(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def font_check(pdf_path: str | Path) -> list[str]:
    """Sind die verlangten Schriften wirklich im PDF gelandet?

    WeasyPrint meldet eine fehlende Schrift nur als Warnung und setzt mit einer
    Ersatzschrift weiter. Dann stehen im Bericht wieder ae, oe und ue statt Umlauten
    (Falle R14 aus spec/04), und niemand merkt es. Geprueft wird deshalb am fertigen
    Dokument und nicht an der Absicht des Stylesheets.
    """
    vorhanden = {_flach(n) for n in embedded_fonts(pdf_path)}
    if not vorhanden:
        return []
    fehlend = [f for f in REQUIRED_FONTS
               if not any(_flach(f) in n for n in vorhanden)]
    return [f"Schrift nicht eingebettet: {f}" for f in fehlend]


# ----------------------------------------------------------------- Layout (S6b-1)
# spec/09 Teil 3: Kicker allein am Seitenende, Posture-Karten und Bilder rechts ueber dem
# Satzspiegel, halbleere Seiten, die die Wortzahl nicht fand (JW 25, HE 18, CA 17 und 23).
# Gemessen wird am gesetzten Dokument ueber WeasyPrints Seitenboxen. Das ist keine
# oeffentliche API; fehlt ein Attribut, liefert ``layout_scan`` None und der Renderer
# meldet das als Warnung, statt still nichts zu pruefen.

# Unter dieser Fuellhoehe gilt eine Seite als halbleer (Deckblatt und letzte Seite
# ausgenommen: das Deckblatt ist gestaltet, die letzte Seite endet, wo der Text endet).
FILL_MIN = 0.5
# Toleranz fuer den Satzspiegel in CSS-Pixeln (96 je Zoll, rund 0,5 mm).
OVERFLOW_TOLERANCE = 2.0


@dataclass
class Layout:
    fill: tuple[float, ...] = ()
    kicker_pages: tuple[int, ...] = ()
    heading_pages: tuple[int, ...] = ()
    overflow: tuple[str, ...] = ()
    # Nachtrag 3 (Entscheidung DC 25.09.): Ursache je halbleerer Seite, als Satz.
    sparse_causes: tuple[str, ...] = ()


# Bloecke, die in der Ursachenmeldung mit Namen stehen (Klasse im Template).
BLOCK_NAMES: dict[str, str] = {
    "fd": "Befundkarte", "svc": "Service-Karte", "post": "Posture-Tabelle",
    "ev": "Nachweisblock", "box": "Hinweiskasten", "cat": "Kategorieblock",
    "lever": "Hebel", "shots": "Bildschirmfotos", "wrapup": "Abschlussblock",
    "impblock": "Impressum", "lastpage": "Anhang D bis F",
}
PX_MM = 25.4 / 96


def _style(box: Any, key: str) -> str:
    try:
        return str(box.style[key])
    except (KeyError, TypeError, AttributeError):
        return ""


def _first_line(box: Any, ancestors: list[Any], B: Any) -> tuple[Any, list[Any]] | None:
    """Erste Text- oder Bildzeile unter ``box`` samt ihrer Vorfahren (ohne Randboxen)."""
    if isinstance(box, (B.LineBox, B.ReplacedBox)):
        return box, ancestors
    for child in getattr(box, "children", None) or ():
        if isinstance(child, B.MarginBox):
            continue
        found = _first_line(child, ancestors + [box], B)
        if found is not None:
            return found
    return None


def _snippet(element: Any, limit: int = 60) -> str:
    try:
        text = " ".join("".join(element.itertext()).split())
    except AttributeError:
        return ""
    return text[:limit] + ("..." if len(text) > limit else "")


def sparse_cause(page_no: int, free_mm: float, next_page: Any, B: Any) -> str:
    """Warum Seite ``page_no`` halbleer blieb: womit die Folgeseite beginnt."""
    found = _first_line(next_page, [], B)
    if found is None:
        return f"Seite {page_no}: {free_mm:.0f} mm frei, Folgeseite ohne Inhalt"
    _, ancestors = found
    classes = [_classes(a) for a in ancestors]
    if any({"kicker", "sec-head"} & c for c in classes):
        return (f"Seite {page_no}: {free_mm:.0f} mm frei, danach beginnt ein Kapitel "
                "mit erzwungenem Seitenwechsel")
    sperre = next((i for i, a in enumerate(ancestors)
                   if getattr(a, "element", None) is not None and _style(a, "break_inside") == "avoid"),
                  None)
    if sperre is None:
        return (f"Seite {page_no}: {free_mm:.0f} mm frei, die Folgeseite beginnt mit "
                "umbrechbarem Inhalt (Umbruch davor)")
    block = ancestors[sperre]
    name, element = "", getattr(block, "element", None)
    for a, c in zip(reversed(ancestors[: sperre + 1]), reversed(classes[: sperre + 1])):
        treffer = next((BLOCK_NAMES[k] for k in c if k in BLOCK_NAMES), "")
        if treffer:
            name, element = treffer, a.element
            break
    name = name or f"<{getattr(block, 'element_tag', '?')}>"
    height = block.margin_height() * PX_MM
    text = _snippet(element)
    return (f"Seite {page_no}: {free_mm:.0f} mm frei, die Folgeseite beginnt mit einem nicht "
            f"umbrechbaren Block ({name}, {height:.0f} mm hoch){': ' + text if text else ''}")


def _classes(box: Any) -> set[str]:
    element = getattr(box, "element", None)
    if element is None or not hasattr(element, "get"):
        return set()
    return set((element.get("class") or "").split())


def _cause_safe(page_no: int, free_mm: float, next_page: Any, B: Any) -> str:
    """Die Ursachenmeldung darf die Layoutpruefung nicht kippen."""
    try:
        return sparse_cause(page_no, free_mm, next_page._page_box, B)
    except (AttributeError, TypeError, KeyError, ValueError):
        return f"Seite {page_no}: {free_mm:.0f} mm frei, Ursache nicht bestimmbar"


def layout_scan(document: Any) -> Layout | None:
    """Fuellhoehe je Seite, Kicker ohne Ueberschrift, Boxen ausserhalb des Satzspiegels."""
    try:
        from weasyprint.formatting_structure import boxes as B
    except ImportError:
        return None
    try:
        fill: list[float] = []
        free_mm: list[float] = []
        events: list[tuple[int, str, int]] = []
        heading_last: list[int] = []
        overflow: set[str] = set()
        for index, page in enumerate(document.pages, start=1):
            page_box = page._page_box
            top = page_box.content_box_y()
            height = page_box.height or 1
            right = page_box.content_box_x() + page_box.width
            bottom = top
            last_kind = ""
            seen: set[tuple[str, int]] = set()
            for child in page_box.children:
                if isinstance(child, B.MarginBox):
                    continue
                for box in child.descendants():
                    if isinstance(box, (B.LineBox, B.ReplacedBox)):
                        bottom = max(bottom, box.position_y + box.margin_height())
                        last_kind = "text"
                    element = getattr(box, "element", None)
                    tag = getattr(box, "element_tag", "")
                    klassen = _classes(box)
                    if element is not None and "kicker" in klassen and ("kicker", id(element)) not in seen:
                        seen.add(("kicker", id(element)))
                        events.append((index, "kicker", id(element)))
                    if element is not None and tag == "h2" and ("h2", id(element)) not in seen:
                        seen.add(("h2", id(element)))
                        events.append((index, "h2", id(element)))
                    if tag in ("h3", "h4") and isinstance(box, B.BlockBox):
                        last_kind = "heading"
                    if isinstance(box, B.BlockBox) and element is not None and "cover" not in klassen:
                        rechts = box.border_box_x() + box.border_width()
                        if rechts > right + OVERFLOW_TOLERANCE and klassen:
                            overflow.add(f"Seite {index}: {' '.join(sorted(klassen))}")
            fill.append(round(max(0.0, (bottom - top) / height), 3))
            free_mm.append(max(0.0, height - (bottom - top)) * PX_MM)
            if last_kind == "heading":
                heading_last.append(index)
        kicker_pages: list[int] = []
        for i, (page_no, kind, _) in enumerate(events):
            if kind != "kicker":
                continue
            folgt = next((e for e in events[i + 1:] if e[1] == "h2"), None)
            if folgt is None or folgt[0] != page_no:
                kicker_pages.append(page_no)
        pages = document.pages
        causes = tuple(_cause_safe(p, free_mm[p - 1], pages[p], B)
                       for p in sparse_from_fill(tuple(fill)) if p < len(pages))
        return Layout(fill=tuple(fill), kicker_pages=tuple(kicker_pages),
                      heading_pages=tuple(heading_last), overflow=tuple(sorted(overflow)),
                      sparse_causes=causes)
    except (AttributeError, TypeError):
        return None


def sparse_from_fill(fill: tuple[float, ...], *, minimum: float = FILL_MIN) -> tuple[int, ...]:
    """Halbleere Seiten: Fuellhoehe unter ``minimum``, ohne Deckblatt und letzte Seite."""
    last = len(fill)
    return tuple(i for i, f in enumerate(fill, start=1) if f < minimum and i not in (1, last))


def text_of(html: str) -> str:
    """Sichtbarer Text eines HTML-Dokuments, grob aber ausreichend fuer Tests."""
    import html as _html

    body = _STYLE.sub(" ", html)
    return _html.unescape(_TAG.sub(" ", body))
