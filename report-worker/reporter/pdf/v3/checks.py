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


def text_of(html: str) -> str:
    """Sichtbarer Text eines HTML-Dokuments, grob aber ausreichend fuer Tests."""
    import html as _html

    body = _STYLE.sub(" ", html)
    return _html.unescape(_TAG.sub(" ", body))
